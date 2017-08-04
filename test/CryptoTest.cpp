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
    testCrypt.cryptKey(key);

    // Test root page encrypt / decrypt
    Buffer tmp;
    ASSERT_NO_THROW(testCrypt.encrypt(1, test1, tmp));
    ASSERT_NO_THROW(testCrypt.decrypt(1, tmp, test2));

    ASSERT_EQ(test1, test2);

    // test normal page encrypt / decrypt
    ASSERT_NO_THROW(testCrypt.encrypt(2, test1, tmp));
    ASSERT_NO_THROW(testCrypt.decrypt(2, tmp, test2));

    ASSERT_EQ(test1, test2);
}