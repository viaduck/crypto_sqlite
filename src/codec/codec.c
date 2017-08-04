#include <sqlite3.c>
#include <stdint.h>
#include <stdio.h>
#include "cinterface.h"

static void *g_codec = NULL;

int sqlite3PagerReadFileheader(Pager *pPager, int N, unsigned char *pDest) {
    // if no codec was set, pass through to original
    if (NULL == g_codec)
        return _sqlite3PagerReadFileheader(pPager, N, pDest);

    codecSetHeaderSize(g_codec, N);
    return codecGetHeader(g_codec, pDest);
}

void sqlite3_prepare_open_encrypted(const char *zFilename, const void *zKey, int nKey) {
    // create a new codec and set its keyfile key
    g_codec = codecCreate(zFilename, zKey, nKey);
}

int sqlite3_open_encrypted(const char *zFilename, sqlite3 **ppDb, const void *zKey, int nKey) {
    // if no key was specified, just open the DB without attaching a codec
    if (zKey == NULL || nKey <= 0)
        return sqlite3_open(zFilename, ppDb);

    // prepare the call to open
    sqlite3_prepare_open_encrypted(zFilename, zKey, nKey);

    int rc = sqlite3_open(zFilename, ppDb);

    if (rc == SQLITE_OK)
        rc = sqlite3_key(*ppDb, zKey, nKey);

    return rc;
}

int sqlite3_rekey_encrypted(const char *zFilename, const void *zKeyOld, int nKeyOld, const void *zKeyNew, int nKeyNew) {
    // create temp codec with old key
    g_codec = codecCreate(zFilename, zKeyOld, nKeyOld);

    // temp ptr
    sqlite3 *pDB;

    // open db to trigger read of header
    int rc = sqlite3_open(zFilename, &pDB);

    if (rc == SQLITE_OK) {
        codecRekey(g_codec, zKeyNew, nKeyNew);
        rc = sqlite3_close(pDB);
    }

    // delete temp codec
    codecDelete(g_codec);

    return rc;
}

void* sqlite3Codec(void* codec, void* data, Pgno pageNum, int mode) {
    if (NULL != codec) {
        // redirect to encrypt/decrypt based on mode
        switch(mode) {
            case 0: // Undo a "case 7" journal file encryption
            case 2: // Reload a page
            case 3: // Load a page
                codecDecrypt(codec, pageNum, (unsigned char*) data);
                break;
            case 6: // Encrypt a page for main db
            case 7: // Encrypt a page for journal
                return codecEncrypt(codec, pageNum, (unsigned char*) data);
            default:
                break;
        }
    }

    // in case no key is set, return plaintext data
    return data;
}

void sqlite3_activate_see(const char* info) { }

void sqlite3PagerFreeCodec(void* codec) {
    codecDelete(codec);
}

void sqlite3CodecSizeChange(void* codec, int pageSize, int reserve) {
    codecSetPageSize(codec, pageSize);
}

int sqlite3CodecAttach(sqlite3* db, int nDb, const void* zKey, int nKey) {
    // lock while modifying page size
    sqlite3_mutex_enter(db->mutex);

    // Set page size to its default, but add our size to be reserved at the end of the page
    sqlite3BtreeSetPageSize(db->aDb[0].pBt, sqlite3BtreeGetPageSize(db->aDb[0].pBt), codecReservedSize(), 0);

    void *pCodec = NULL;

    // no key specified, either attached DB or no encryption
    if (NULL == zKey || nKey <= 0) {
        // attached DB, use main DB's key
        if (0 != nDb && nKey < 0) {
            // get codec of main DB
            void *pMainCodec = sqlite3PagerGetCodec(sqlite3BtreePager(db->aDb[0].pBt));

            // main DB is encrypted -> encrypt attached DB using duplicate codec
            if (NULL != pMainCodec)
                pCodec = codecDuplicate(pMainCodec);
        }
    } else {
        // key specified, use previously prepared codec
        pCodec = g_codec;
        g_codec = NULL;
    }

    if (NULL != pCodec)
        sqlite3PagerSetCodec(sqlite3BtreePager(db->aDb[nDb].pBt), sqlite3Codec, sqlite3CodecSizeChange,
                             sqlite3PagerFreeCodec, pCodec);

    sqlite3_mutex_leave(db->mutex);
    return SQLITE_OK;
}

int sqlite3_rekey(sqlite3* db, const void* zKey, int nKey) {
    void *pCodec = sqlite3PagerGetCodec(sqlite3BtreePager(db->aDb[0].pBt));

    // Case 1: DB not encrypted, no key specified -> do nothing
    if ((NULL == zKey || 0 == nKey) && NULL == pCodec)
        return SQLITE_OK;

    // Case 2: DB not encrypted, key specified -> fail
    if (NULL == pCodec)
        return SQLITE_ERROR;

    // Case 3: DB encrypted, no key specified -> fail
    if (NULL == zKey || 0 == nKey)
        return SQLITE_ERROR;

    // Case 4: DB encrypted, other key specified -> fail
    return SQLITE_ERROR;
}

int sqlite3_key(sqlite3* db, const void* zKey, int nKey) {
    // The key is only set for the main database, not the temp database
    return sqlite3CodecAttach(db, 0, zKey, nKey);
}

int sqlite3_rekey_v2(sqlite3* db, const char* zDbName, const void* zKey, int nKey) {
    //We don't use zDbName (though maybe we could...). Pass-through to the old sqlite_rekey
    return sqlite3_rekey(db, zKey, nKey);
}

int sqlite3_key_v2(sqlite3* db, const char* zDbName, const void* zKey, int nKey) {
    //We don't use zDbName (though maybe we could...). Pass-through to the old sqlite_key
    return sqlite3_key(db, zKey, nKey);
}

void sqlite3CodecGetKey(sqlite3* db, int nDb, void** zKey, int* nKey) {
    // The unencrypted password is not stored for security reasons therefore always return NULL
    *zKey = NULL;
    *nKey = -1;
}

