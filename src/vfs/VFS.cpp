/*
 * Copyright (C) 2020 The ViaDuck Project
 *
 * This file is part of CryptoSQLite.
 *
 * CryptoSQLite is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * CryptoSQLite is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with CryptoSQLite.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <algorithm>
#include "VFS.h"

VFS VFS::sInstance;

VFS::VFS() : mBase(), mDBs(new std::vector<File *>()) {
    // find default VFS
    mUnderlying = sqlite3_vfs_find(nullptr);

    // set base parameters based on underlying VFS
    mBase = {
            3,                      /* iVersion */
            static_cast<int>(sizeof(File) + mUnderlying->szOsFile),                      /* szOsFile */
            mUnderlying->mxPathname,                   /* mxPathname */
            nullptr,                /* pNext */
            "CryptoSQLite",         /* zName */
            nullptr,                /* pAppData */
            sVfsOpen,               /* xOpen */
            sVfsDelete,             /* xDelete */
            sVfsAccess,             /* xAccess */
            sVfsFullPathname,       /* xFullPathname */
            sVfsDlOpen,             /* xDlOpen */
            sVfsDlError,            /* xDlError */
            sVfsDlSym,              /* xDlSym */
            sVfsDlClose,            /* xDlClose */
            sVfsRandomness,         /* xRandomness */
            sVfsSleep,              /* xSleep */
            sVfsCurrentTime,        /* xCurrentTime */
            sVfsGetLastError,       /* xGetLastError */
            sVfsCurrentTimeInt64,   /* xCurrentTimeInt64 */
            sVfsSetSystemCall,      /* xSetSystemCall */
            sVfsGetSystemCall,      /* xGetSystemCall */
            sVfsNextSystemCall      /* xNextSystemCall */
    };
}

VFS::~VFS() {
    delete mDBs;
}

void VFS::prepare(const void *zKey, int nKey) {
    // make custom VFS default before opening
    sqlite3_vfs_register(base(), 1);
    // cache key in instance for open()
    mFileKey = zKey;
    mFileKeySize = nKey;
}

int VFS::open(const char *zName, sqlite3_file *pFile, int flags, int *pOutFlags) {
    auto *db = reinterpret_cast<File *>(pFile);

    db->mUnderlying = reinterpret_cast<sqlite3_file *>(&db[1]);
    db->mFileName = zName;
    db->mExists = 0;
    db->mOpenFlags = flags;
    db->mCrypto = nullptr;
    db->mDB = nullptr;
    db->mPageNo = 0;

    if (zName) {
        switch (flags & SQLITE_OPEN_MASK) {
            /** Contains only administrative information, no encryption necessary. **/
            case SQLITE_OPEN_MASTER_JOURNAL:
            case SQLITE_OPEN_TEMP_DB:
                break;

            case SQLITE_OPEN_MAIN_DB:
                VFS_FORWARD(this, xAccess, zName, SQLITE_ACCESS_EXISTS, &db->mExists);
                db->mCrypto = new Crypto(db->mFileName, mFileKey, mFileKeySize, db->mExists);
                break;

            case SQLITE_OPEN_MAIN_JOURNAL:
            case SQLITE_OPEN_SUBJOURNAL:
            case SQLITE_OPEN_WAL:
                db->mDB = findMainDatabase(zName);
                db->mCrypto = db->mDB->mCrypto;
                break;

            case SQLITE_OPEN_TRANSIENT_DB:
            case SQLITE_OPEN_TEMP_JOURNAL:
                // TODO ?
                break;

            default:
                return SQLITE_ERROR;
        }
    }

    int ret = VFS_FORWARD(this, xOpen, zName, db->mUnderlying, flags, pOutFlags);
    if (ret == SQLITE_OK) {
        pFile->pMethods = &File::gSQLiteIOMethods;

        if (flags & SQLITE_OPEN_MAIN_DB)
            addDatabase(db);
    }
    return ret;
}

void VFS::finish() {
    mFileKey = nullptr;
    mFileKeySize = 0;
    // unregister custom VFS after opening
    sqlite3_vfs_unregister(VFS::instance()->base());
}

File *VFS::findMainDatabase(const char *name) {
    auto *dbFileName = sqlite3_filename_database(name);

    SQLite3LockGuard lock(mMutex);
    auto it = std::find_if(mDBs->begin(), mDBs->end(), [dbFileName] (auto *db) {
        return db->mFileName == dbFileName;
    });

    return (it != mDBs->end()) ? *it : nullptr;
}

void VFS::addDatabase(File *db) {
    SQLite3LockGuard lock(mMutex);
    mDBs->push_back(db);
}

void VFS::removeDatabase(File *db) {
    SQLite3LockGuard lock(mMutex);
    mDBs->erase(std::remove_if(mDBs->begin(), mDBs->end(), [db] (auto it) {
        return it == db;
    }), mDBs->end());
}
