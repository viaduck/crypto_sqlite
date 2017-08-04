#include <string>
#include "cinterface.h"
#include <cryptosqlite/Codec.h>
#include <cryptosqlite/FileWrapper.h>

// Convenience methods

Codec *toCodec(void *ptr) {
    return static_cast<Codec*>(ptr);
}

const Codec *toCodec(const void *ptr) {
    return static_cast<const Codec*>(ptr);
}

// interface methods forwarding calls

void *codecCreate(const char *databaseName, const void* key, int keylen) {
    // create buffer wrapper for key
    Buffer keyBuffer;
    keyBuffer.write(key, keylen, 0);

    return new Codec(databaseName, keyBuffer);
}

void *codecDuplicate(const void *other) {
    return new Codec(*toCodec(other));
}

void codecDelete(void *codec) {
    delete toCodec(codec);
}

unsigned char *codecEncrypt(void *codec, Pgno page, unsigned char *data) {
    return toCodec(codec)->encrypt(page, data);
}

void codecDecrypt(void *codec, Pgno page, unsigned char *data) {
    toCodec(codec)->decrypt(page, data);
}

void codecRekey(void *codec, const void *key, int keylen) {
    // create buffer wrapper
    Buffer newKeyBuffer;
    newKeyBuffer.write(key, keylen, 0);

    toCodec(codec)->rekey(newKeyBuffer);
}

int codecReservedSize() {
    return Codec::RESERVED_SIZE;
}

void codecSetPageSize(void *codec, int pageSize) {
    toCodec(codec)->pageSize(pageSize);
}

void codecSetHeaderSize(void *codec, int headerSize) {
    toCodec(codec)->headerSize(headerSize);
}

int codecGetHeader(void *codec, unsigned char *destination) {
    try {
        Buffer tempDest;
        toCodec(codec)->getHeader(tempDest);
        memcpy(destination, tempDest.const_data(), tempDest.size());
    } catch (const cryptosqlite_exception &) {
        codecDelete(codec);
        return SQLITE_NOTADB;
    }
    return SQLITE_OK;
}