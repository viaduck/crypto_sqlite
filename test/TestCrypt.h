/*
 * Copyright (C) 2017-2018 The ViaDuck Project
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

#ifndef CRYPTOSQLITE_TESTCRYPT_H
#define CRYPTOSQLITE_TESTCRYPT_H

#include <crypto_sqlite/crypto/IDataCrypt.h>

class TestCrypt : public IDataCrypt {
public:
    void encrypt(uint32_t page, const Buffer &source, Buffer &destination, const Buffer &key) const override {
        // copy source to destination
        destination.write(source, 0);

        // xor destination with key
        xorBuffer(destination, key);
    }

    void decrypt(uint32_t page, const Buffer &source, Buffer &destination, const Buffer &key) const override {
        // since XOR operation is the same, just encrypt again to decrypt
        encrypt(page, source, destination, key);
    }

    void generateKey(Buffer &destination) const override {
        String testKey("sometestkey1234");
        destination.write(testKey, 0);
    }

    void wrapKey(Buffer &wrappedKey, const Buffer &key, const Buffer &wrappingKey) const override {
        wrappedKey.append(key);
        xorBuffer(wrappedKey, wrappingKey);
    }

    void unwrapKey(Buffer &key, const Buffer &wrappedKey, const Buffer &wrappingKey) const override {
        key.append(wrappedKey);
        xorBuffer(key, wrappingKey);
    }

    uint32_t extraSize() const override { return 16; }

protected:
    static void xorBuffer(BufferRange sourceDest, const Buffer &key) {
        for (uint32_t i = 0; i < sourceDest.size() && key.size(); i += key.size())
            for (uint32_t j = 0; j < key.size(); j++)
                *sourceDest.data(i + j) ^= *key.const_data(j);
    }
};

#endif //CRYPTOSQLITE_TESTCRYPT_H
