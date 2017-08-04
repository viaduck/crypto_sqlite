#ifndef CRYPTOSQLITE_CODEC_H
#define CRYPTOSQLITE_CODEC_H

#include <memory>
#include <functional>
#include <cstring>
#include <secure_memory/Buffer.h>

#include <cryptosqlite/encryption/IDataCrypt.h>
#include "FileWrapper.h"

class Codec {
public:
    using CryptoFactory = std::function<void(std::unique_ptr<IDataCrypt>&)>;

    // Note: keep this between 0 and 255 because sqlite3 asserts that
    static const int RESERVED_SIZE = 255;

    static void setCryptoFactory(CryptoFactory factory) {
        sFactoryCrypt = std::move(factory);
    }

    explicit Codec(const std::string &dbname, const Buffer &keyFileKey) : mKeyFile(dbname + ".keyfile") {
        initCrypto();
        mCrypt->fileKey(keyFileKey);
    }

    Codec(const Codec &other) : mKeyFile(other.mKeyFile) {
        initCrypto();
        other.mCrypt->clone(mCrypt);
    }

    unsigned char *encrypt(uint32_t page, unsigned char *data);

    void decrypt(uint32_t page, unsigned char *data);

    void rekey(const Buffer &newFileKey);

    void getHeader(Buffer &destinationHeader);

    bool hasKey() {
        return mCrypt->hasKey();
    }

    void pageSize(int size) {
        mCrypt->pageSize(size);
    }

    void headerSize(int size) {
        mCrypt->headerSize(size);
    }

protected:
    void writeHeader(const Buffer &header) {
        Buffer rawFileData;

        try {
            mCrypt->encryptKeyFile(rawFileData, header, mCrypt->cryptKey());
        }
        catch (const std::exception &) {
            throw cryptosqlite_exception("Keyfile could not be encrypted");
        }

        mKeyFile.writeFile(rawFileData);
    }

    std::unique_ptr<IDataCrypt> mCrypt;

    Buffer mSource, mDestination;

    FileWrapper mKeyFile;

    static CryptoFactory sFactoryCrypt;

private:
    void initCrypto() {
        if (!sFactoryCrypt)
            throw cryptosqlite_exception("No crypto factory set.");

        sFactoryCrypt(mCrypt);
    }
};

#endif //CRYPTOSQLITE_CODEC_H
