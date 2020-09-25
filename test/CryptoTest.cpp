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
#include "CryptoTest.h"
#include "TestCrypt.h"

TEST_F(CryptoTest, testTestCrypt) {
    String test1("kajlskjalksalsdjlkasdjlkasjdlkajsdlkjalejoiquoaijlakjdlksajdlkjaierojlkasiue3jwlalkajlskjalksalsdjlk"
                         "asdjlkasjdlkajsdlkjalejoiquoaijlakjdlksajdlkjaierojlkasiue3jwlalkajlskjalksalsdjlkasdjlkasjd"
                         "lkajsdlkjalejoiquoaijlakjdlksajdlkjaierojlkasiue3jwlalkajlskjalksalsdjlkasdjlkasjdlkajsdlkja"
                         "lejoiquoaijlakjdlksajdlkjaierojlkasiue3jwlal"), test2;

    String key("asjlkaslkajs");

    TestCrypt testCrypt;

    // Test root page encrypt / decrypt
    Buffer tmp;
    testCrypt.encrypt(1, test1, tmp, key);
    testCrypt.decrypt(1, tmp, test2, key);

    ASSERT_EQ(test1, test2);

    // test normal page encrypt / decrypt
    testCrypt.encrypt(2, test1, tmp, key);
    testCrypt.decrypt(2, tmp, test2, key);

    ASSERT_EQ(test1, test2);
}