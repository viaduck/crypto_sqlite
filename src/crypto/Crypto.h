/*
 * Copyright (C) 2020 The ViaDuck Project
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
#ifndef CRYPTOSQLITE_CRYPTO_H
#define CRYPTOSQLITE_CRYPTO_H

#include <cryptosqlite/crypto/IDataCrypt.h>

class Crypto {
public:
    Crypto(const std::string &dbFileName, const void *fileKey, int keylen, int exists);
    void writeKey(const std::string &dbFileName, const void *fileKey, int keylen);
    void readKey(const std::string &dbFileName, const void *fileKey, int keylen);

    const void *encryptPage(const void *pageIn, uint32_t pageSize, int pageNo);
    void decryptPage(void *pageInOut, uint32_t pageSize, int pageNo);

    uint32_t extraSize();

    void resizePageBuffers(uint32_t size) {
        mPageBufferIn.padd(size, 0);
        mPageBufferOut.padd(size, 0);
    }
    uint8_t *pageBufferIn() { return static_cast<uint8_t *>(mPageBufferIn.data()); }
    const uint8_t *pageBufferOut() { return static_cast<const uint8_t *>(mPageBufferOut.const_data()); }

protected:
    std::unique_ptr<IDataCrypt> mDataCrypt;
    Buffer mKey, mPageBufferIn, mPageBufferOut;
};

#endif //CRYPTOSQLITE_CRYPTO_H
