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
