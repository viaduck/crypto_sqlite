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
