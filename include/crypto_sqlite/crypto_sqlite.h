/*
 * Copyright (C) 2017-2020 The ViaDuck Project
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

#ifndef CRYPTOSQLITE_CRYPTOSQLITE_H
#define CRYPTOSQLITE_CRYPTOSQLITE_H

#include <memory>
#include <functional>
#include <secure_memory/Buffer.h>
#include <crypto_sqlite/crypto/IDataCrypt.h>

class crypto_sqlite_exception : public std::runtime_error {
public:
    explicit crypto_sqlite_exception(const std::string &msg) : std::runtime_error(msg) { }
};

class crypto_sqlite {
public:
    using CryptoFactory = std::function<void(std::unique_ptr<IDataCrypt>&)>;

    static void setCryptoFactory(CryptoFactory factory) {
        sFactoryCrypt = std::move(factory);
    }

    static void makeDataCrypt(std::unique_ptr<IDataCrypt> &out) {
        if (!sFactoryCrypt)
            throw crypto_sqlite_exception("No crypto factory set.");

        sFactoryCrypt(out);
    }

protected:
    static CryptoFactory sFactoryCrypt;
};

extern "C" {
#include <sqlite3.h>
SQLITE_API void sqlite3_prepare_open_encrypted(const void *zKey, int nKey);
SQLITE_API int sqlite3_open_encrypted(const char *zFilename, sqlite3 **ppDb, const void *zKey, int nKey);
SQLITE_API int sqlite3_rekey_encrypted(const char *zFilename, const void *zKeyOld, int nKeyOld, const void *zKeyNew, int nKeyNew);
SQLITE_API int sqlite3_key(sqlite3* db, const void* zKey, int nKey);
};

#endif //CRYPTOSQLITE_CRYPTOSQLITE_H
