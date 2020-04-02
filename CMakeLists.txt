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

cmake_minimum_required(VERSION 3.1)
project(cryptoSQLite)

# set cmake module path
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/external/securememory/cmake-modules")

# enable and require c++14
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# add sqlite amalgamation subdirectory and tests
add_subdirectory(sqlite)
add_subdirectory(test)

if (NOT TARGET SecureMemory)
    add_subdirectory(external/securememory)
endif()

if (NOT TARGET icu)
    add_subdirectory(external/icu-cmake)
endif()

# glob files
file(GLOB_RECURSE CS_INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/include/*)
file(GLOB_RECURSE CS_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/*)

# set up library target
add_library(cryptosqlite STATIC ${CS_INCLUDES} ${CS_SOURCES})

# compile options
target_compile_options(cryptosqlite PRIVATE
    -Wall
    -Wextra
    -Wno-sign-compare
    -Wno-unused-parameter
    -Wno-implicit-fallthrough
    -Wno-unused-function
    )

# link options
target_link_libraries(cryptosqlite SecureMemory icu)
if (NOT WIN32)
    target_link_libraries(cryptosqlite dl)
endif()

# add compile definitions to match this specific use case
target_compile_definitions(cryptosqlite PUBLIC
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
    target_compile_definitions(cryptosqlite PUBLIC
            # Required due to unix having 8-byte boundaries.
            -DSQLITE_4_BYTE_ALIGNED_MALLOC=1
            )
else()
    target_compile_definitions(cryptosqlite PUBLIC
            # Use threadsafe localtime
            -DHAVE_LOCALTIME_R
            )
endif()

# add public codec definition to publics
target_compile_definitions(cryptosqlite PUBLIC
        # encryption layer added as codec
        -DSQLITE_HAS_CODEC
        )

# export includes to other targets
target_include_directories(cryptosqlite PUBLIC
        ${SQLITE_INCLUDES}
        ${CMAKE_CURRENT_SOURCE_DIR}/include/
        )
