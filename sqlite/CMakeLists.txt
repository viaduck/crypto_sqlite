# set up cache variables
set(SQLITE_VERSION "3200000" CACHE STRING "SQLite version string as used in the URL")
set(SQLITE_YEAR "2017" CACHE STRING "SQLite year string as used in the URL")
set(SQLITE_SHA1 "6786fced716237689cfa8212265967f28cef5de9" CACHE STRING
        "SQLite amalgamation zip sha1 hash used to check the dowload")

# build url from cache variables
string(CONCAT SQLITE_URL "https://sqlite.org/" ${SQLITE_YEAR} "/sqlite-amalgamation-" ${SQLITE_VERSION} ".zip")
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
        EXPECTED_HASH SHA1=${SQLITE_SHA1}
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