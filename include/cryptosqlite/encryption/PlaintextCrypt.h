#ifndef CRYPTOSQLITE_PLAINTEXTCRYPT_H
#define CRYPTOSQLITE_PLAINTEXTCRYPT_H

#include <cstring>
#include <secure_memory/Buffer.h>
#include <secure_memory/BufferRange.h>
#include "IDataCrypt.h"

class PlaintextCrypt : public IDataCrypt {
public:
    void encrypt(uint32_t, const Buffer &source, Buffer &destination) const override {
        destination.write(source, 0);
    }

    void decrypt(uint32_t, const Buffer &source, Buffer &destination) const override {
        destination.write(source, 0);
    }

    void generateKey(Buffer &) const override { }

    void encryptKeyFile(Buffer &destination, const Buffer &header, const Buffer &) const override {
        destination.write(header, 0);
    }

    void decryptKeyFile(const Buffer &source, Buffer &destHeader, Buffer &) const override {
        destHeader.write(source, 0);
    }
};


#endif //CRYPTOSQLITE_PLAINTEXTCRYPT_H
