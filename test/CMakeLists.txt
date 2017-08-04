# find system gtest
find_package(GTest)

if (GTEST_FOUND)
    # find test files
    file(GLOB_RECURSE TEST_SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp)
    file(GLOB_RECURSE TEST_INCLUDE ${CMAKE_CURRENT_SOURCE_DIR}/*.h)

    # include gtest
    include_directories(${GTEST_INCLUDE_DIRS})

    # basic test executable
    add_executable(CryptoSQLiteTest ${TEST_SOURCE} ${TEST_INCLUDE})

    # add dependencies
    target_link_libraries(CryptoSQLiteTest ${GTEST_BOTH_LIBRARIES} pthread cryptosqlite)
endif()