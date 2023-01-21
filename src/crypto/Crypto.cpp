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
#include "Crypto.h"

#include "FileWrapper.h"
#include <crypto_sqlite/crypto_sqlite.h>

Crypto::Crypto(const std::string &dbFileName, const void *fileKey, int keylen, int exists)
        : mFileName(dbFileName + "-keyfile") {
    crypto_sqlite::makeDataCrypt(mDataCrypt);

    if (!exists) {
        // generate new key and wrap it to buffer
        mDataCrypt->generateKey(mKey);
        wrapKey(fileKey, keylen);
    }
    else {
        // read existing keyfile and unwrap key
        readKeyFile();
        unwrapKey(fileKey, keylen);
    }
}

void Crypto::rekey(const void *newFileKey, int keylen) {
    wrapKey(newFileKey, keylen);
    writeKeyFile();
}

void Crypto::wrapKey(const void *fileKey, int keylen) {
    Buffer wrappingKey;
    wrappingKey.write(fileKey, keylen, 0);

    mWrappedKey.clear();
    mDataCrypt->wrapKey(mWrappedKey, mKey, wrappingKey);
}

void Crypto::unwrapKey(const void *fileKey, int keylen) {
    Buffer wrappingKey;
    wrappingKey.write(fileKey, keylen, 0);

    mKey.clear();
    mDataCrypt->unwrapKey(mKey, mWrappedKey, wrappingKey);
}

void Crypto::writeKeyFile() {
    Buffer content;
    mWrappedKey.serializeAppend(content);
    mFirstPage.serializeAppend(content);

    FileWrapper keyfile(mFileName);
    keyfile.writeFile(content);
}

void Crypto::readKeyFile() {
    Buffer content;
    FileWrapper keyfile(mFileName);
    keyfile.readFile(content);

    BufferRangeConst chain(content);
    mWrappedKey.deserialize(chain);
    mFirstPage.deserialize(chain);
}

const void *Crypto::encryptPage(const void *page, uint32_t pageSize, int pageNo) {
    // copy plaintext to input buffer
    mPageBufferIn.write(page, pageSize, 0);
    // encrypt to output buffer
    mDataCrypt->encrypt(pageNo, mPageBufferIn, mPageBufferOut, mKey);
    // cache encrypted first page and write it to keyfile
    if (pageNo == 1) {
        mFirstPage.clear();
        mFirstPage.write(mPageBufferOut, 0);
        writeKeyFile();
    }
    // return pointer to point to ciphertext
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

void Crypto::decryptFirstPageCache() {
    // fit page buffers to cache or minimum page size if cache empty
    resizePageBuffers(std::max(mFirstPage.size(), 512u));
    // decrypt first page from cache or leave 0-bytes if cache empty
    if (mFirstPage.size() > 0) mDataCrypt->decrypt(1, mFirstPage, mPageBufferOut, mKey);
}

void Crypto::resizePageBuffers(uint32_t size) {
    mPageBufferIn.clear();
    mPageBufferIn.padd(size, 0);

    mPageBufferOut.clear();
    mPageBufferOut.padd(size, 0);
}

uint32_t Crypto::extraSize() {
    return mDataCrypt->extraSize();
}
