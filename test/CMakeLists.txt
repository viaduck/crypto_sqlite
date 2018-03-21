# Copyright (c) 2017-2018 The ViaDuck Project
#
# This file is part of cryptoSQLite.
#
# cryptoSQLite is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# cryptoSQLite is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with cryptoSQLite.  If not, see <http://www.gnu.org/licenses/>.
#

include(FindOrBuildGTest)

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