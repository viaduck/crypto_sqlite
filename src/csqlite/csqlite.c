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

// must be first include
#include <sqlite3.c>
#include "csqlite.h"

struct sqlite3_mutex *csqlite3_get_mutex(struct sqlite3 *db) {
    return db->mutex;
}

void csqlite3_reserve_page(sqlite3 *db, int nDb, int *pageSize, int reservedSize) {
    *pageSize = sqlite3BtreeGetPageSize(db->aDb[nDb].pBt);
    sqlite3BtreeSetPageSize(db->aDb[nDb].pBt, *pageSize, reservedSize, 1);
}

uint32_t csqlite3_get4byte(const uint8_t *data) {
    return sqlite3Get4byte(data);
}
