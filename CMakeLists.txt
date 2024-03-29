# Copyright (c) 2017-2024 The ViaDuck Project
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

cmake_minimum_required(VERSION 3.1...3.27)
project(crypto_sqlite)

# options
option(CRYPTO_SQLITE_BUILD_TESTS "Enable test compilation for crypto_sqlite" OFF)

# set cmake module path
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/external/secure_memory/cmake-modules")

# add sqlite amalgamation subdirectory and tests
add_subdirectory(sqlite)

if (NOT TARGET secure_memory)
    add_subdirectory(external/secure_memory)
endif()

if (NOT TARGET icu)
    add_subdirectory(external/icu-cmake)
endif()

# glob files
file(GLOB_RECURSE CS_INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/include/*)
file(GLOB_RECURSE CS_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/*)

# set up library target
add_library(crypto_sqlite STATIC ${CS_INCLUDES} ${CS_SOURCES})

# require and enable c++14 support
set_target_properties(crypto_sqlite PROPERTIES CXX_STANDARD 14 CXX_STANDARD_REQUIRED YES)

# compile options
target_compile_options(crypto_sqlite PRIVATE
    -Wall
    -Wextra
    -Wno-sign-compare
    -Wno-unused-parameter
    -Wno-implicit-fallthrough
    -Wno-unused-function
    )

# link options
target_link_libraries(crypto_sqlite secure_memory icu)
if (NOT WIN32)
    target_link_libraries(crypto_sqlite dl)
endif()

# add compile definitions to match this specific use case
target_compile_definitions(crypto_sqlite PUBLIC
        # Serialized -> free to use same connection/statement in different threads
        -DSQLITE_THREADSAFE=1
        # No need for another memory watcher
        -DSQLITE_DEFAULT_MEMSTATUS=0
        # Always use memory for temporary files
        -DSQLITE_TEMP_STORE=3
        # Use the new write ahead logging
        -DSQLITE_DEFAULT_WAL_SYNCHRONOUS=1
        # Do not allow searching in BLOBs by using LIKE or GLOB.
        -DSQLITE_LIKE_DOESNT_MATCH_BLOBS=1
        # We don't need checking the depth of the expression tree as queries won't be that complex.
        -DSQLITE_MAX_EXPR_DEPTH=0
        # Do not use any deprecated features as deprecated is not so good.
        -DSQLITE_OMIT_DEPRECATED=1
        # Since we are using sqlite async, we do not need this
        -DSQLITE_OMIT_PROGRESS_CALLBACK=1
        # Using this is supported on all platforms we care about and improves VFS performance
        -DHAVE_FDATASYNC
        # Use perfomant isnan system version
        -DHAVE_ISNAN
        # Use interface to get malloc available size
        -DHAVE_MALLOC_USABLE_SIZE
        # Readable and writeable by user only
        -DSQLITE_DEFAULT_FILE_PERMISSIONS=0600
        # Hardening always makes sense.
        -DSQLITE_ENABLE_API_ARMOR
        # Full text search
        -DSQLITE_ENABLE_FTS4
        -DSQLITE_ENABLE_FTS5
        # Unicode support for strings in comparators
        -DSQLITE_ENABLE_ICU
        # Enable JSON extension support
        -DSQLITE_ENABLE_JSON1
        )

if (WIN32)
    target_compile_definitions(crypto_sqlite PUBLIC
            # Required due to unix having 8-byte boundaries.
            -DSQLITE_4_BYTE_ALIGNED_MALLOC=1
            )
else()
    target_compile_definitions(crypto_sqlite PUBLIC
            # Use threadsafe localtime
            -DHAVE_LOCALTIME_R
            )
endif()

# export includes to other targets
target_include_directories(crypto_sqlite PUBLIC
        ${SQLITE_INCLUDES}
        ${CMAKE_CURRENT_SOURCE_DIR}/include/
        )

# tests
if (CRYPTO_SQLITE_BUILD_TESTS)
    add_subdirectory(test)
endif()
