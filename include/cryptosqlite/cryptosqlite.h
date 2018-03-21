/*
 * Copyright (C) 2017-2018 The ViaDuck Project
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

#ifndef CRYPTOSQLITE_CRYPTOSQLITE_H_H
#define CRYPTOSQLITE_CRYPTOSQLITE_H_H

class cryptosqlite_exception : public std::runtime_error {
public:
    explicit cryptosqlite_exception(const std::string &msg) : std::runtime_error(msg) { }
};

extern "C" {
#include <sqlite3.h>
SQLITE_API void sqlite3_prepare_open_encrypted(const char *zFilename, const void *zKey, int nKey);
SQLITE_API int sqlite3_open_encrypted(const char *zFilename, sqlite3 **ppDb, const void *zKey, int nKey);
SQLITE_API int sqlite3_rekey_encrypted(const char *zFilename, const void *zKeyOld, int nKeyOld, const void *zKeyNew, int nKeyNew);
};

#endif //CRYPTOSQLITE_CRYPTOSQLITE_H_H
