/*
 * Copyright (C) 2017-2020 The ViaDuck Project
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

#include <cryptosqlite/cryptosqlite.h>
#include "vfs/VFS.h"

cryptosqlite::CryptoFactory cryptosqlite::sFactoryCrypt;

void sqlite3_prepare_open_encrypted() {
    // make custom VFS default before opening
    sqlite3_vfs_register(VFS::instance()->base(), 1);
}

int sqlite3_open_encrypted(const char *zFilename, sqlite3 **ppDb, const void *zKey, int nKey) {
    // no key specified
    if (zKey == nullptr || nKey <= 0)
        return sqlite3_open(zFilename, ppDb);

    // prepare the call to open
    sqlite3_prepare_open_encrypted();

    int rc = sqlite3_open(zFilename, ppDb);
    if (rc == SQLITE_OK)
        rc = sqlite3_key(*ppDb, zKey, nKey);

    return rc;
}

int sqlite3_rekey_encrypted(const char *zFilename, const void *zKeyOld, int nKeyOld, const void *zKeyNew, int nKeyNew) {
    // temp db
    sqlite3 *pDB;

    // open temp db encrypted
    int rc = sqlite3_open_encrypted(zFilename, &pDB, zKeyOld, nKeyOld);
    if (rc == SQLITE_OK) {
        // find main db file
        const char *fileName = sqlite3_db_filename(pDB, "main");
        File *mainDB = VFS::instance()->findMainDatabase(fileName);

        // write keyfile with new file key
        if (mainDB && mainDB->mCrypto) {
            mainDB->mCrypto->writeKey(zFilename, zKeyNew, nKeyNew);
            rc = sqlite3_close(pDB);
        } else {
            rc = SQLITE_ERROR;
            sqlite3_close(pDB);
        }
    }

    return rc;
}

int sqlite3_key(sqlite3* db, const void* zKey, int nKey) {
    // The key is only set for the main database, not the temp database
    const char *fileName = sqlite3_db_filename(db, "main");
    File *mainDB = VFS::instance()->findMainDatabase(fileName);
    if (!mainDB)
        return SQLITE_ERROR;

    // attach to db
    int rv = mainDB->attach(db, 0, zKey, nKey);

    // unregister custom VFS after opening
    sqlite3_vfs_unregister(VFS::instance()->base());
    return rv;
}
