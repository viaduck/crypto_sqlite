#ifndef CRYPTOSQLITE_CODECINTERFACE_H
#define CRYPTOSQLITE_CODECINTERFACE_H


#ifdef __cplusplus
    #include <cstdint>

    extern "C" {
#else
    #include <stdint.h>
    #include <stdbool.h>
#endif

typedef uint32_t Pgno;

void *codecCreate(const char *databaseName, const void *key, int keylen);
void *codecDuplicate(const void *other);
void codecDelete(void *codec);

unsigned char *codecEncrypt(void *codec, Pgno page, unsigned char *data);
void codecDecrypt(void *codec, Pgno page, unsigned char *data);
void codecRekey(void *codec, const void *key, int keylen);

int codecReservedSize();
void codecSetPageSize(void *codec, int pageSize);
void codecSetHeaderSize(void *codec, int headerSize);
int codecGetHeader(void *codec, unsigned char *destination);

#ifdef __cplusplus
    }
#endif

#endif //CRYPTOSQLITE_CODECINTERFACE_H
