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
#include "Crypto.h"

#include "FileWrapper.h"
#include <cryptosqlite/cryptosqlite.h>

Crypto::Crypto(const std::string &dbFileName, const void *fileKey, int keylen, int exists) {
    cryptosqlite::makeDataCrypt(mDataCrypt);

    if (!exists) {
        // generate new key and wrap it to file
        mDataCrypt->generateKey(mKey);
        writeKey(dbFileName, fileKey, keylen);
    }
    else {
        // read existing key and unwrap it
        readKey(dbFileName, fileKey, keylen);
    }
}

void Crypto::writeKey(const std::string &dbFileName, const void *fileKey, int keylen) {
    Buffer wrappingKey, wrappedKey;
    wrappingKey.write(fileKey, keylen, 0);

    FileWrapper keyfile(dbFileName + "-keyfile");
    mDataCrypt->wrapKey(wrappedKey, mKey, wrappingKey);
    keyfile.writeFile(wrappedKey);
}

void Crypto::readKey(const std::string &dbFileName, const void *fileKey, int keylen) {
    Buffer wrappingKey, wrappedKey;
    wrappingKey.write(fileKey, keylen, 0);

    FileWrapper keyfile(dbFileName + "-keyfile");
    keyfile.readFile(wrappedKey);
    mDataCrypt->unwrapKey(mKey, wrappedKey, wrappingKey);
}

const void *Crypto::encryptPage(const void *page, uint32_t pageSize, int pageNo) {
    // copy plaintext to input buffer
    mPageBufferIn.write(page, pageSize, 0);
    // encrypt to output buffer
    mDataCrypt->encrypt(pageNo, mPageBufferIn, mPageBufferOut, mKey);
    // replace pointer to point to ciphertext
    return pageBufferOut();
}

void Crypto::decryptPage(void *pageInOut, uint32_t pageSize, int pageNo) {
    // copy ciphertext to input buffer
    if (pageInOut) mPageBufferIn.write(pageInOut, pageSize, 0);
    // decrypt to output buffer
    mDataCrypt->decrypt(pageNo, mPageBufferIn, mPageBufferOut, mKey);
    // overwrite ciphertext with plaintext
    if (pageInOut) memcpy(pageInOut, pageBufferOut(), pageSize);
}

uint32_t Crypto::extraSize() {
    return mDataCrypt->extraSize();
}
