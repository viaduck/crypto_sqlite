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

#ifndef CRYPTOSQLITE_IDATACRYPT_H
#define CRYPTOSQLITE_IDATACRYPT_H

#include <string>

class IDataCrypt {
public:
    virtual void encrypt(uint32_t page, const Buffer &source, Buffer &destination) const = 0;
    virtual void decrypt(uint32_t page, const Buffer &source, Buffer &destination) const = 0;

    const Buffer &cryptKey() const {
        return mKey;
    }

    virtual void cryptKey(const Buffer &key) {
        mKey.clear();
        mKey.write(key, 0);
    }

    bool hasKey() const {
        return mKey.size() != 0;
    }

protected:
    virtual void generateKey(Buffer &destination) const = 0;
    virtual void encryptKeyFile(Buffer &destination, const Buffer &header, const Buffer &key) const = 0;
    virtual void decryptKeyFile(const Buffer &source, Buffer &destHeader, Buffer &destKey) const = 0;

    virtual void fileKey(const Buffer &key) {
        mFileKey.clear();
        mFileKey.write(key, 0);
    }

    uint32_t pageSize() const {
        return mPageSize;
    }

    virtual void pageSize(uint32_t size) {
        mPageSize = size;
    }

    uint32_t headerSize() const {
        return mHeaderSize;
    }

    virtual void headerSize(uint32_t size) {
        mHeaderSize = size;
    }

    virtual void clone(std::unique_ptr<IDataCrypt> &other) {
        other->mKey.write(mKey, 0);
        other->mFileKey.write(mFileKey, 0);
        other->mPageSize = mPageSize;
        other->mHeaderSize = mHeaderSize;
    }

    Buffer mKey, mFileKey;
    uint32_t mPageSize = 0, mHeaderSize = 0;

    friend class Codec;
};

#endif //CRYPTOSQLITE_IDATACRYPT_H
