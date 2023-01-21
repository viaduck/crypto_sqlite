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

#ifndef CRYPTOSQLITE_IDATACRYPT_H
#define CRYPTOSQLITE_IDATACRYPT_H

#include <string>
#include <secure_memory/String.h>

class IDataCrypt {
public:
    virtual ~IDataCrypt() = default;

    virtual void encrypt(uint32_t page, const Buffer &source, Buffer &destination, const Buffer &key) const = 0;
    virtual void decrypt(uint32_t page, const Buffer &source, Buffer &destination, const Buffer &key) const = 0;

    virtual void generateKey(Buffer &destination) const = 0;
    virtual void unwrapKey(Buffer &key, const Buffer &wrappedKey, const Buffer &wrappingKey) const = 0;
    virtual void wrapKey(Buffer &wrappedKey, const Buffer &key, const Buffer &wrappingKey) const = 0;

    virtual uint32_t extraSize() const = 0;
};

#endif //CRYPTOSQLITE_IDATACRYPT_H
