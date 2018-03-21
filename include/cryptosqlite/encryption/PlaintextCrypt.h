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

#ifndef CRYPTOSQLITE_PLAINTEXTCRYPT_H
#define CRYPTOSQLITE_PLAINTEXTCRYPT_H

#include <cstring>
#include <secure_memory/Buffer.h>
#include <secure_memory/BufferRange.h>
#include "IDataCrypt.h"

class PlaintextCrypt : public IDataCrypt {
public:
    void encrypt(uint32_t, const Buffer &source, Buffer &destination) const override {
        destination.write(source, 0);
    }

    void decrypt(uint32_t, const Buffer &source, Buffer &destination) const override {
        destination.write(source, 0);
    }

    void generateKey(Buffer &) const override { }

    void encryptKeyFile(Buffer &destination, const Buffer &header, const Buffer &) const override {
        destination.write(header, 0);
    }

    void decryptKeyFile(const Buffer &source, Buffer &destHeader, Buffer &) const override {
        destHeader.write(source, 0);
    }
};


#endif //CRYPTOSQLITE_PLAINTEXTCRYPT_H
