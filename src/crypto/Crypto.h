/*
 * Copyright (C) 2020-2025 The ViaDuck Project
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
#ifndef CRYPTOSQLITE_CRYPTO_H
#define CRYPTOSQLITE_CRYPTO_H

#include <crypto_sqlite/crypto/IDataCrypt.h>

class Crypto {
public:
    Crypto(const std::string &dbFileName, const void *fileKey, int keylen, int exists);

    void rekey(const void *newFileKey, int keylen);
    const void *encryptPage(const void *pageIn, uint32_t pageSize, int pageNo);
    void decryptPage(void *pageInOut, uint32_t pageSize, int pageNo);
    void decryptFirstPageCache();

    uint32_t extraSize() const;

    void resizePageBuffers(uint32_t size);
    uint8_t *pageBufferIn() { return mPageBufferIn.data(); }
    const uint8_t *pageBufferOut() const { return mPageBufferOut.const_data(); }

protected:
    void wrapKey(const void *fileKey, int keylen);
    void unwrapKey(const void *fileKey, int keylen);
    void writeKeyFile();
    void readKeyFile();

    // extern crypto plugin
    std::unique_ptr<IDataCrypt> mDataCrypt;
    // keyfile name
    std::string mFileName;
    // cache
    Buffer mWrappedKey, mFirstPage;
    // state, input, output
    Buffer mKey, mPageBufferIn, mPageBufferOut;
};

#endif //CRYPTOSQLITE_CRYPTO_H
