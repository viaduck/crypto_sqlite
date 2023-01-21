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
#ifndef CRYPTOSQLITE_CSQLITE_H
#define CRYPTOSQLITE_CSQLITE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sqlite3.h>
#include <stdint.h>

sqlite3_mutex *csqlite3_get_mutex(sqlite3 *db);
void csqlite3_reserve_page(sqlite3 *db, int nDb, int *pageSize, int reservedSize);
uint32_t csqlite3_get4byte(const uint8_t *data);

#ifdef __cplusplus
};
#endif
#endif //CRYPTOSQLITE_CSQLITE_H
