/*
 * Copyright (C) 2020 The ViaDuck Project
 *
 * This file is part of cryptoSQLite.
 *
 * cryptoSQLite is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * cryptoSQLite is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with cryptoSQLite.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <cstring>
#include <cassert>
#include "../vfs/VFS.h"
#include "../csqlite/csqlite.h"
#include "File.h"

sqlite3_io_methods File::gSQLiteIOMethods = {
        3,                          /* iVersion */
        sIoClose,                  /* xClose */
        sIoRead,                   /* xRead */
        sIoWrite,                  /* xWrite */
        sIoTruncate,               /* xTruncate */
        sIoSync,                   /* xSync */
        sIoFileSize,               /* xFileSize */
        sIoLock,                   /* xLock */
        sIoUnlock,                 /* xUnlock */
        sIoCheckReservedLock,      /* xCheckReservedLock */
        sIoFileControl,            /* xFileControl */
        sIoSectorSize,             /* xSectorSize */
        sIoDeviceCharacteristics,  /* xDeviceCharacteristics */
        sIoShmMap,                 /* xShmMap */
        sIoShmLock,                /* xShmLock */
        sIoShmBarrier,             /* xShmBarrier */
        sIoShmUnmap,               /* xShmUnmap */
        sIoFetch,                  /* xFetch */
        sIoUnfetch,                /* xUnfetch */
};

int File::attach(sqlite3 *db, int nDb, const void *zKey, int nKey) {
    // lock while modifying page size
    SQLite3Mutex mutex(csqlite3_get_mutex(db));
    SQLite3LockGuard lock(mutex);

    // no key specified, either attached DB or no encryption
    if (!zKey || nKey <= 0) {
        // attached DB, use main DB's key
        if (0 != nDb && nKey < 0) {
            // TODO: get crypto of main DB
            void *pMainCrypto = nullptr;

            // main DB is encrypted -> encrypt attached DB using duplicate codec
            if (pMainCrypto) {
                ; // TODO: duplicate pMainCrypto here
            }
        }
    } else {
        // key specified
        mCrypto = new Crypto(mFileName, zKey, nKey, mExists);
    }

    // Set page size to its default, but add our size to be reserved at the end of the page
    csqlite3_reserve_page(db, nDb, &mPageSize, mCrypto->extraSize());
    mCrypto->resizePageBuffers(mPageSize);
    return SQLITE_OK;
}

int File::close() {
    // clean from list
    if (mOpenFlags & SQLITE_OPEN_MAIN_DB)
        VFS::instance()->removeDatabase(this);

    // cleanup state
    if (!mDB) delete mCrypto;
    mCrypto = nullptr;

    // forward actual close
    return mUnderlying->pMethods->xClose(mUnderlying);
}

int File::read(void *buffer, int count, sqlite3_int64 offset) {
    // forward actual read
    auto rv = FILE_FORWARD(this, xRead, buffer, count, offset);
    if (rv != SQLITE_OK)
        return rv;

    if (mCrypto) {
        switch (mOpenFlags & SQLITE_OPEN_MASK) {
            case SQLITE_OPEN_MAIN_DB:
                return readMainDB(buffer, count, offset);

            case SQLITE_OPEN_MAIN_JOURNAL:
            case SQLITE_OPEN_SUBJOURNAL:
                return readJournal(buffer, count, offset);

            case SQLITE_OPEN_WAL:
                return readWal(buffer, count, offset);

            case SQLITE_OPEN_TEMP_DB:
            case SQLITE_OPEN_TRANSIENT_DB:
            case SQLITE_OPEN_TEMP_JOURNAL:
                // TODO ?
                break;

            case SQLITE_OPEN_MASTER_JOURNAL:
                /** Contains only administrative information, no encryption necessary. **/
            default:
                break;
        }
    }

    return rv;
}

int File::write(const void *buffer, int count, sqlite3_int64 offset) {
    if (mCrypto) {
        switch (mOpenFlags & SQLITE_OPEN_MASK) {
            case SQLITE_OPEN_MAIN_DB:
                return writeMainDB(buffer, count, offset);

            case SQLITE_OPEN_MAIN_JOURNAL:
            case SQLITE_OPEN_SUBJOURNAL:
                return writeJournal(buffer, count, offset);

            case SQLITE_OPEN_WAL:
                return writeWal(buffer, count, offset);

            case SQLITE_OPEN_TEMP_DB:
            case SQLITE_OPEN_TRANSIENT_DB:
            case SQLITE_OPEN_TEMP_JOURNAL:
                // TODO ?
                break;

            case SQLITE_OPEN_MASTER_JOURNAL:
                /** Contains only administrative information, no encryption necessary. **/
            default:
                break;
        }
    }

    // forward actual write
    return FILE_FORWARD(this, xWrite, buffer, count, offset);
}

int File::readMainDB(void *buffer, int count, sqlite3_int64 offset) {
    int rv = SQLITE_OK;

    // special case: read 16 byte salt from beginning of DB unencrypted
    if (offset == 0 && count == 16)
        return rv;

    // prepare values
    int dOffset = offset % mPageSize;

    if (count != 0 || dOffset != 0) {
        // do partial page read
        assert(dOffset + count <= mPageSize);
        sqlite3_int64 prevOffset = offset - dOffset;

        // read full page with new parameters
        rv = FILE_FORWARD(this, xRead, mCrypto->pageBufferIn(), mPageSize, prevOffset);
        if (rv != SQLITE_OK)
            return rv;

        // calculate page number and decrypt
        int pageNo = prevOffset / mPageSize + 1;
        mCrypto->decryptPage(nullptr, mPageSize, pageNo);

        // return data
        memcpy(buffer, mCrypto->pageBufferOut() + dOffset, count);
    }
    else {
        // do full page read
        assert(count == mPageSize);

        int pageNo = offset / mPageSize + 1;
        mCrypto->decryptPage(buffer, mPageSize, pageNo);
    }

    return rv;
}

int File::readJournal(void *buffer, int count, sqlite3_int64) {
    if (count == mPageSize && mPageNo != 0) {
        // decrypt page buffer
        mCrypto->decryptPage(buffer, mPageSize, mPageNo);
        mPageNo = 0;
    }
    else if (count == 4) {
        // sqlite always reads the pageno from journal file before reading page content
        mPageNo = csqlite3_get4byte(static_cast<uint8_t*>(buffer));
    }

    return SQLITE_OK;
}

int File::readWal(void *buffer, int count, sqlite_int64 offset) {
    int rv = SQLITE_OK;

    if (count == mPageSize) {
        int pageNo;
        uint8_t temp[4];

        rv = FILE_FORWARD(this, xRead, temp, 4, offset - SQLITE_WAL_FRAMEHEADER_SIZE);
        if (rv == SQLITE_OK && (pageNo = csqlite3_get4byte(temp)) != 0) {
            // decrypt page buffer
            mCrypto->decryptPage(buffer, mPageSize, pageNo);
        }
    }

    return rv;
}

int File::writeMainDB(const void *buffer, int count, sqlite3_int64 offset) {
    // only full page writes
    assert(offset % mPageSize == 0 && count == mPageSize);

    int pageNo = offset / mPageSize + 1;
    buffer = mCrypto->encryptPage(buffer, mPageSize, pageNo);

    return FILE_FORWARD(this, xWrite, buffer, mPageSize, offset);
}

int File::writeJournal(const void *buffer, int count, sqlite3_int64 offset) {
    int rv = SQLITE_OK;

    if (count == mPageSize && mPageNo != 0) {
        // encrypt full page buffer
        buffer = mCrypto->encryptPage(buffer, mPageSize, mPageNo);
        rv = FILE_FORWARD(this, xWrite, buffer, mPageSize, offset);
    }
    else {
        // write partial non-page data without encryption
        rv = FILE_FORWARD(this, xWrite, buffer, count, offset);
        if (count == 4)
            mPageNo = rv == SQLITE_OK ? csqlite3_get4byte(static_cast<const uint8_t*>(buffer)) : 0u;
    }

    return rv;
}

int File::writeWal(const void *buffer, int count, sqlite3_int64 offset) {
    int rv = SQLITE_OK;

    if (count == mPageSize) {
        int pageNo;
        uint8_t temp[4];

        // read page number from file before writing the page
        rv = FILE_FORWARD(this, xRead, temp, 4, offset - SQLITE_WAL_FRAMEHEADER_SIZE);
        if (rv != SQLITE_OK)
            return rv;

        // page number should always be valid
        pageNo = csqlite3_get4byte(temp);
        assert(pageNo != 0);

        // encrypt full page buffer
        buffer = mCrypto->encryptPage(buffer, mPageSize, pageNo);
        rv = FILE_FORWARD(this, xWrite, buffer, mPageSize, offset);
    }
    else {
        // write partial non-page data without encryption
        rv = FILE_FORWARD(this, xWrite, buffer, count, offset);
    }

    return rv;
}
