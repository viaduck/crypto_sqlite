#ifndef CRYPTOSQLITE_BASICTEST_H
#define CRYPTOSQLITE_BASICTEST_H

#include <gtest/gtest.h>
#include <sqlite3.h>
#include <cryptosqlite/Codec.h>
#include "TestCrypt.h"

class BasicTest : public ::testing::Test {
protected:
    virtual void SetUp() override {
        std::remove("test.db");
        std::remove("test.db.keyfile");
    }

    void testReadWrite(const char *key, int keylen, bool transact = false, int insertCount = 1000) {
        testWrite(key, keylen, transact, insertCount);
        testRead(key, keylen, insertCount);
    }

    void testWrite(const char *key, int keylen, bool transact = false, int insertCount = 1000);
    void testRead(const char *key, int keylen, int insertCount = 1000);
    void testRekey(const char *oldkey, int oldkeylen, const char *newkey, int newkeylen);
    void testOpenFail(const char *key, int keylen);
};


#endif //CRYPTOSQLITE_BASICTEST_H
