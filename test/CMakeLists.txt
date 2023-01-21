# Copyright (c) 2017-2021 The ViaDuck Project
#
# This file is part of CryptoSQLite.
#
# CryptoSQLite is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# CryptoSQLite is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with CryptoSQLite.  If not, see <http://www.gnu.org/licenses/>.
#

include(FindOrBuildGTest)

if (GTEST_FOUND)
    # find test files
    file(GLOB_RECURSE TEST_SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp)
    file(GLOB_RECURSE TEST_INCLUDE ${CMAKE_CURRENT_SOURCE_DIR}/*.h)

    # include gtest
    include_directories(${GTEST_INCLUDE_DIRS})

    # basic test executable
    add_executable(crypto_sqlite_test ${TEST_SOURCE} ${TEST_INCLUDE})

    # require and enable c++14 support
    set_target_properties(crypto_sqlite_test PROPERTIES CXX_STANDARD 14 CXX_STANDARD_REQUIRED YES)

    # add dependencies
    target_link_libraries(crypto_sqlite_test ${GTEST_BOTH_LIBRARIES} crypto_sqlite)
    if (NOT ANDROID)
        target_link_libraries(crypto_sqlite_test pthread)
    endif()
endif()
