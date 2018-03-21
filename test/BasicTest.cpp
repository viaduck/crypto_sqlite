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

#include <secure_memory/String.h>
#include <cryptosqlite/cryptosqlite.h>
#include <cryptosqlite/encryption/PlaintextCrypt.h>
#include "BasicTest.h"

#define ASSERT_OK(x) ASSERT_EQ(SQLITE_OK, (x))
#define ASSERT_DONE(x) ASSERT_EQ(SQLITE_DONE, (x))

TEST_F(BasicTest, testNoPW) {
    testReadWrite(nullptr, 0);
}

TEST_F(BasicTest, testNoPWTransact) {
    testReadWrite(nullptr, 0, true);
}

TEST_F(BasicTest, testPlaintext) {
    Codec::setCryptoFactory([] (std::unique_ptr<IDataCrypt> &crypt) {
        crypt.reset(new PlaintextCrypt());
    });

    const char *key = "1234";
    int keylen = 4;

    testReadWrite(key, keylen);
}

TEST_F(BasicTest, testPlaintextTransact) {
    Codec::setCryptoFactory([] (std::unique_ptr<IDataCrypt> &crypt) {
        crypt.reset(new PlaintextCrypt());
    });

    const char *key = "1234";
    int keylen = 4;

    testReadWrite(key, keylen, true);
}

TEST_F(BasicTest, testPlaintextTransactRekey) {
    Codec::setCryptoFactory([] (std::unique_ptr<IDataCrypt> &crypt) {
        crypt.reset(new PlaintextCrypt());
    });

    const char *key = "1234", *newkey = "32818";
    int keylen = 4, newlen = 5;

    testWrite(key, keylen, true);
    testRekey(key, keylen, newkey, newlen);
    testRead(newkey, newlen);
}

TEST_F(BasicTest, testTestCrypt) {
    Codec::setCryptoFactory([] (std::unique_ptr<IDataCrypt> &crypt) {
        crypt.reset(new TestCrypt());
    });

    const char *key = "42424242";
    int keylen = strlen(key);

    testReadWrite(key, keylen);
}

TEST_F(BasicTest, testTestCryptTransact) {
    Codec::setCryptoFactory([] (std::unique_ptr<IDataCrypt> &crypt) {
        crypt.reset(new TestCrypt());
    });

    const char *key = "42424242";
    int keylen = strlen(key);

    testReadWrite(key, keylen, true);
}

TEST_F(BasicTest, testTestCryptTransactRekey) {
    Codec::setCryptoFactory([] (std::unique_ptr<IDataCrypt> &crypt) {
        crypt.reset(new TestCrypt());
    });

    const char *key = "42424242", *newkey = "8921897129818";
    int keylen = strlen(key), newlen = strlen(newkey);

    testWrite(key, keylen, true);
    testRekey(key, keylen, newkey, newlen);
    testRead(newkey, newlen);
}

void BasicTest::testWrite(const char *key, int keylen, bool transact, int insertCount) {
    // test params
    const char* dbName = "test.db";

    const char * CREATE_TABLE_TEST = "create table 'test' (id INTEGER PRIMARY KEY, name TEXT);";
    const char * INSERT_PREPARE = "insert into 'test' VALUES (?, ?);";
    const char * BEGIN_TRANSACT = "BEGIN TRANSACTION;";
    const char * END_TRANSACT = "END TRANSACTION;";

    // test variables
    sqlite3 *db;
    sqlite3_stmt *prep_st;
    char* error = nullptr;

    ASSERT_OK(sqlite3_open_encrypted(dbName, &db, key, keylen));

    // start transaction
    if (transact)
        ASSERT_OK(sqlite3_exec(db, BEGIN_TRANSACT, nullptr, nullptr, &error));

    // create DB
    ASSERT_OK(sqlite3_exec(db, CREATE_TABLE_TEST, nullptr, nullptr, &error));

    // prepare statement
    ASSERT_OK(sqlite3_prepare_v2(db, INSERT_PREPARE, -1, &prep_st, nullptr));

    for (int i = 0; i < insertCount; i++) {
        std::string teststr = "hanswurst" + std::to_string(i);

        // bind it
        ASSERT_OK(sqlite3_bind_int(prep_st, 1, i));
        ASSERT_OK(sqlite3_bind_text(prep_st, 2, teststr.c_str(), teststr.size(), nullptr));

        // run it
        ASSERT_DONE(sqlite3_step(prep_st));

        // reset it
        ASSERT_OK(sqlite3_reset(prep_st));
    }

    // commit transaction
    if (transact)
        ASSERT_OK(sqlite3_exec(db, END_TRANSACT, nullptr, nullptr, &error));

    // close DB before selecting to test decryption and force load from disk
    ASSERT_OK(sqlite3_finalize(prep_st));
    ASSERT_OK(sqlite3_close(db));
}

void BasicTest::testRead(const char *key, int keylen, int insertCount) {
    // test params
    const char* dbName = "test.db";

    const char * SELECT = "select * FROM 'test';";

    // test variables
    sqlite3 *db;
    char* error = nullptr;

    // open DB
    ASSERT_OK(sqlite3_open_encrypted(dbName, &db, key, keylen));

    int count = 0;

    ASSERT_OK(sqlite3_exec(db, SELECT, [] (void *data, int argc, char **argv, char **azColName) -> int {
        std::string id(argv[0]);
        std::string name(argv[1]);

        EXPECT_EQ("hanswurst" + id, name);

        int * counter = (int*)data;
        (*counter)++;

        return 0;
    }, &count, &error));


    ASSERT_EQ(insertCount, count);
    ASSERT_OK(sqlite3_close(db));
}

void BasicTest::testRekey(const char *oldkey, int oldkeylen, const char *newkey, int newkeylen) {
    // test params
    const char* dbName = "test.db";

    // open DB
    ASSERT_OK(sqlite3_rekey_encrypted(dbName, oldkey, oldkeylen, newkey, newkeylen));
}
