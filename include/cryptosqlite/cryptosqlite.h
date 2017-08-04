#ifndef CRYPTOSQLITE_CRYPTOSQLITE_H_H
#define CRYPTOSQLITE_CRYPTOSQLITE_H_H

class cryptosqlite_exception : public std::runtime_error {
public:
    explicit cryptosqlite_exception(const std::string &msg) : std::runtime_error(msg) { }
};

extern "C" {
#include <sqlite3.h>
SQLITE_API void sqlite3_prepare_open_encrypted(const char *zFilename, const void *zKey, int nKey);
SQLITE_API int sqlite3_open_encrypted(const char *zFilename, sqlite3 **ppDb, const void *zKey, int nKey);
SQLITE_API int sqlite3_rekey_encrypted(const char *zFilename, const void *zKeyOld, int nKeyOld, const void *zKeyNew, int nKeyNew);
};

#endif //CRYPTOSQLITE_CRYPTOSQLITE_H_H
