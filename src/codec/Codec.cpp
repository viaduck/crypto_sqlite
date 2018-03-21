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

#include <cryptosqlite/Codec.h>
#include <cryptosqlite/cryptosqlite.h>

Codec::CryptoFactory Codec::sFactoryCrypt;

unsigned char *Codec::encrypt(uint32_t page, unsigned char *data) {
    if (!mCrypt->hasKey())
        return data;

    // handle first page separately
    if (page == 1) {
        // copy header to dedicated buffer
        Buffer header;
        header.write(data, mCrypt->headerSize(), 0);

        // put header in keyfile
        writeHeader(header);
    }

    // write plaintext to source
    mSource.write(data, mCrypt->pageSize(), 0);

    // encrypt source to destination
    mCrypt->encrypt(page, mSource, mDestination);

    // return destination pointer
    return static_cast<unsigned char *>(mDestination.data());
}

void Codec::decrypt(uint32_t page, unsigned char *data) {
    if (!mCrypt->hasKey())
        return;

    // write plaintext to source
    mSource.write(data, mCrypt->pageSize(), 0);

    // decrypt source to destination
    mCrypt->decrypt(page, mSource, mDestination);

    // copy plaintext back to data
    memcpy(data, mDestination.const_data(), mCrypt->pageSize());
}

void Codec::rekey(const Buffer &newFileKey) {
    Buffer rawFileData, headerData, keyData;

    // read keyfile in
    mKeyFile.readFile(rawFileData);

    // decrypt keyfile to header and key data
    try {
        mCrypt->decryptKeyFile(rawFileData, headerData, keyData);
    }
    catch (const std::exception &) {
        throw cryptosqlite_exception("Keyfile could not be decrypted");
    }

    // change file key
    mCrypt->fileKey(newFileKey);
    // clear old encrypted file data
    rawFileData.clear();

    // re-encrypt header and key data to file data
    try {
        mCrypt->encryptKeyFile(rawFileData, headerData, keyData);
    }
    catch (const std::exception &) {
        throw cryptosqlite_exception("Keyfile could not be encrypted");
    }

    // write newly encrypted data
    mKeyFile.writeFile(rawFileData);
}

void Codec::getHeader(Buffer &destinationHeader) {
    Buffer rawFileData, destinationKey;

    if (mKeyFile.isEmpty()) {
        // pad destination header with specified number of zero bytes as initial header
        destinationHeader.padd(mCrypt->headerSize(), 0);

        try {
            // generate new key and encrypt file
            mCrypt->generateKey(destinationKey);
            mCrypt->encryptKeyFile(rawFileData, destinationHeader, destinationKey);
        }
        catch (const std::exception &) {
            throw cryptosqlite_exception("Keyfile could not be generated");
        }

        mKeyFile.writeFile(rawFileData);
    } else {
        mKeyFile.readFile(rawFileData);

        try {
            mCrypt->decryptKeyFile(rawFileData, destinationHeader, destinationKey);
        }
        catch (const std::exception &) {
            throw cryptosqlite_exception("Keyfile could not be decrypted");
        }
    }

    // use generated / read key for database
    mCrypt->cryptKey(destinationKey);
}
