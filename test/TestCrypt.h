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

#ifndef CRYPTOSQLITE_TESTCRYPT_H
#define CRYPTOSQLITE_TESTCRYPT_H

#include <cryptosqlite/encryption/IDataCrypt.h>
#include <secure_memory/Buffer.h>

class TestCrypt : public IDataCrypt {
public:
    void encrypt(uint32_t page, const Buffer &source, Buffer &destination) const override {
        // copy source to destination
        destination.write(source, 0);

        // xor destination with key
        xorBuffer(destination, mKey);
    }

    void decrypt(uint32_t page, const Buffer &source, Buffer &destination) const override {
        // since XOR operation is the same, just encrypt again to decrypt
        encrypt(page, source, destination);
    }

    void generateKey(Buffer &destination) const override {
        String testKey("sometestkey1234");
        destination.write(testKey, 0);
    }

    void encryptKeyFile(Buffer &destination, const Buffer &header, const Buffer &key) const override {
        destination.append(header);
        destination.append(key);

        xorBuffer(destination, mFileKey);
    }

    void decryptKeyFile(const Buffer &source, Buffer &destHeader, Buffer &destKey) const override {
        Buffer tempPlaintext(source);
        xorBuffer(tempPlaintext, mFileKey);

        destHeader.write(tempPlaintext.const_data(0, mHeaderSize), 0);
        destKey.write(tempPlaintext.const_data(mHeaderSize, tempPlaintext.size() - mHeaderSize), 0);
    }

protected:
    void xorBuffer(BufferRange sourceDest, const Buffer &key) const {
        for (uint32_t i = 0; i < sourceDest.size(); i += key.size())
            for (uint32_t j = 0; j < key.size(); j++)
                *static_cast<uint8_t *>(sourceDest.data(i + j)) ^= *static_cast<const uint8_t *>(key.const_data(j));
    }
};


#endif //CRYPTOSQLITE_TESTCRYPT_H
