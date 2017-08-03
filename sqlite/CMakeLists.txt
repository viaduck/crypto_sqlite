# set up cache variables
set(SQLITE_VERSION "3200000" CACHE STRING "SQLite version string as used in the URL")
set(SQLITE_YEAR "2017" CACHE STRING "SQLite year string as used in the URL")
set(SQLITE_SHA1 "6786fced716237689cfa8212265967f28cef5de9" CACHE STRING
        "SQLite amalgamation zip sha1 hash used to check the dowload")

# build url from cache variables
string(CONCAT SQLITE_URL "https://sqlite.org/" ${SQLITE_YEAR} "/sqlite-amalgamation-" ${SQLITE_VERSION} ".zip")
string(CONCAT SQLITE_SUBDIR "sqlite-amalgamation-" ${SQLITE_VERSION})

# download amalgamation zip with hash check
file(DOWNLOAD
        ${SQLITE_URL}
        ${CMAKE_CURRENT_SOURCE_DIR}/sqlite.zip
        EXPECTED_HASH SHA1=${SQLITE_SHA1}
        SHOW_PROGRESS
        )

# unpack zip only if needed
if (NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/${SQLITE_SUBDIR})

    # unpack the amalgamation zip in current dir
    execute_process(COMMAND ${CMAKE_COMMAND} -E tar x sqlite.zip
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

endif()

# find files just downloaded
file(GLOB_RECURSE SQ_INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/${SQLITE_SUBDIR}/*.h)
set(SQ_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/${SQLITE_SUBDIR}/sqlite3.c)

# add to includes
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/${SQLITE_SUBDIR})

# vanilla sqlite lib
add_library(sqlite ${SQ_INCLUDES} ${SQ_SOURCES})

# associate headers to library, transfer headers to every target depending on sqlite via PUBLIC
target_include_directories(sqlite PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/${SQLITE_SUBDIR})