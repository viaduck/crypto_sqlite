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

# set up cache variables
set(SQLITE_VERSION "3260000" CACHE STRING "SQLite version string as used in the URL")
set(SQLITE_SHA256 "de5dcab133aa339a4cf9e97c40aa6062570086d6085d8f9ad7bc6ddf8a52096e" CACHE STRING
        "SQLite amalgamation zip sha256 hash used to check the download")

# build url from cache variables
string(CONCAT SQLITE_URL "https://mirror.viaduck.org/sqlite/sqlite-amalgamation-" ${SQLITE_VERSION} ".zip")
string(CONCAT SQLITE_SUBDIR "sqlite-amalgamation-" ${SQLITE_VERSION})

# find patch program to apply small patches to sqlite
find_program(PATCH_PROGRAM patch)
if (NOT PATCH_PROGRAM)
    message(FATAL_ERROR "Cannot find patch utility.")
endif()

# find all patch files
file(GLOB_RECURSE PATCH_FILES ${CMAKE_CURRENT_SOURCE_DIR}/patches/*.patch)

# download amalgamation zip with hash check
file(DOWNLOAD
        ${SQLITE_URL}
        ${CMAKE_CURRENT_SOURCE_DIR}/sqlite.zip
        EXPECTED_HASH SHA256=${SQLITE_SHA256}
        SHOW_PROGRESS
        )

# unpack zip only if needed
if (NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/${SQLITE_SUBDIR})

    # unpack the amalgamation zip in current dir
    execute_process(COMMAND ${CMAKE_COMMAND} -E tar x sqlite.zip
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

    foreach(PATCH_FILE ${PATCH_FILES})
        # apply each patch subsequently
        execute_process(COMMAND ${PATCH_PROGRAM} -p1 -i ${PATCH_FILE}
                WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/${SQLITE_SUBDIR}/)
    endforeach()

endif()

# find files just downloaded
file(GLOB_RECURSE SQ_FILES ${CMAKE_CURRENT_SOURCE_DIR}/${SQLITE_SUBDIR}/*)

# export variables to parent scope
set(SQLITE_FILES SQ_FILES PARENT_SCOPE)
set(SQLITE_INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/${SQLITE_SUBDIR}/ PARENT_SCOPE)
