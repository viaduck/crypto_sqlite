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

#ifndef CRYPTOSQLITE_PLAINTEXTCRYPT_H
#define CRYPTOSQLITE_PLAINTEXTCRYPT_H

#include <cstring>
#include <secure_memory/Buffer.h>
#include <secure_memory/BufferRange.h>
#include <crypto_sqlite/crypto/IDataCrypt.h>

class PlaintextCrypt : public IDataCrypt {
public:
    void encrypt(uint32_t, const Buffer &source, Buffer &destination, const Buffer &) const override {
        destination.write(source, 0);
    }
    void decrypt(uint32_t page, const Buffer &source, Buffer &destination, const Buffer &key) const override {
        encrypt(page, source, destination, key);
    }

    void generateKey(Buffer &) const override { }
    void unwrapKey(Buffer &, const Buffer &, const Buffer &) const override { }
    void wrapKey(Buffer &, const Buffer &, const Buffer &) const override { }

    uint32_t extraSize() const override { return 0; }
};


#endif //CRYPTOSQLITE_PLAINTEXTCRYPT_H
