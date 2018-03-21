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

#ifndef CRYPTOSQLITE_CODECINTERFACE_H
#define CRYPTOSQLITE_CODECINTERFACE_H


#ifdef __cplusplus
    #include <cstdint>

    extern "C" {
#else
    #include <stdint.h>
    #include <stdbool.h>
#endif

typedef uint32_t Pgno;

void *codecCreate(const char *databaseName, const void *key, int keylen);
void *codecDuplicate(const void *other);
void codecDelete(void *codec);

unsigned char *codecEncrypt(void *codec, Pgno page, unsigned char *data);
void codecDecrypt(void *codec, Pgno page, unsigned char *data);
void codecRekey(void *codec, const void *key, int keylen);

int codecReservedSize();
void codecSetPageSize(void *codec, int pageSize);
void codecSetHeaderSize(void *codec, int headerSize);
int codecGetHeader(void *codec, unsigned char *destination);

#ifdef __cplusplus
    }
#endif

#endif //CRYPTOSQLITE_CODECINTERFACE_H
