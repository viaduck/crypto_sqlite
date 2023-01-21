# CryptoSQLite
Generic SQLite3 encryption codec C++ interface for encrypting database pages
plus SQLite3 header.

## Features
* transparent usage
* interface: no hard-coded list of ciphers, use your crypto lib of choice
* full page encryption
* SQLite3 file header encryption
* key file support: long encryption key is stored separately, can be protected
with a password)

## Setup
1. Initialize Git submodules: `git submodule update --init --recursive`
2. Link against the `crypto_sqlite` CMake library target.
3. Implement `IDataCrypt` interface (for an example see
[test/TestCrypt.h](test/TestCrypt.h) or
[test/PlaintextCrypt.h](test/PlaintextCrypt.h))

## Usage
Either:

1. `int sqlite3_open_encrypted(const char *fileName, sqlite3 **db, const void
*key, int keySize)`
Or:

1. `void sqlite3_prepare_open_encrypted(const char *fileName, const void *key,
int keySize)`
2. `sqlite3_open`
3. `sqlite3_key`

**Note**: *Opening* multiple encrypted databases at the same time is not
thread-safe, but *using* them is.


## SQLite Compatibility
CryptoSQLite automatically downloads, patches, and compiles the SQLite3
amalgamation source. This logic can be found in
[sqlite/CMakeLists.txt](sqlite/CMakeLists.txt). Updating the used SQLite3
version is achieved by simply modifying the variables in the aforementioned
`CMakeLists.txt`.  
  
The patch exposes a private method required for SQLite3 file header encryption.
Due to its simplicity, the patch should work for newer SQLite3 versions without
changes.

## Related Projects
* [SQLiteModernCPP](https://github.com/SqliteModernCpp/sqlite_modern_cpp):
Modern SQLite3 wrapper
* [CryptoSQLiteCPP](https://github.com/viaduck/cryptosqlitepp): Combines
[SQLiteModernCPP](https://github.com/SqliteModernCpp/sqlite_modern_cpp) and
CryptoSQLite into one Git repository for simplified usage.

## Alternatives
The following alternative projects already supply ciphers to be used for
encryption:

* [SQLite3 Encryption](https://github.com/rindeal/SQLite3-Encryption): AES-based
SQLite3 encryption codec depending on wxSQLite3
* [SQLCipher](https://www.zetetic.net/sqlcipher/): OpenSSL-based partially open
source solution

## Licensing
This library is subject to the GNU Lesser General Public License v3.0 (GNU
LGPLv3).

```
Copyright (C) 2017-2023  The ViaDuck Project

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
```
