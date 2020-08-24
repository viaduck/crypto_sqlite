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

#ifndef CRYPTOSQLITE_BASICTEST_H
#define CRYPTOSQLITE_BASICTEST_H

#include <gtest/gtest.h>
#include <sqlite3.h>
#include <cryptosqlite/crypto/PlaintextCrypt.h>
#include "TestCrypt.h"

class BasicTest : public ::testing::Test {
protected:
    virtual void SetUp() override {
        std::remove("test.db");
        std::remove("test.db-keyfile");
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
