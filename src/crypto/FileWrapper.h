/*
 * Copyright (C) 2017-2020 The ViaDuck Project
 *
 * This file is part of cryptoSQLite.
 *
 * cryptoSQLite is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * cryptoSQLite is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with cryptoSQLite.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef CRYPTOSQLITE_KEYFILE_H
#define CRYPTOSQLITE_KEYFILE_H

#include <cryptosqlite/cryptosqlite.h>
#include <cstdio>

class FileWrapper {
public:
    explicit FileWrapper(const std::string &filename) {
        // try to open existing file
        mFile = fopen(filename.c_str(), "r+b");

        if (nullptr == mFile) {
            // mark file as empty
            mEmpty = true;

            // try to create non existing file
            mFile = fopen(filename.c_str(), "w+b");

            // could not create file
            if (nullptr == mFile)
                throw cryptosqlite_exception("File could not be created");
        }
    }

    ~FileWrapper() {
        if (nullptr != mFile)
            fclose(mFile);
    }

    bool isEmpty() const {
        return mEmpty;
    }

    void writeFile(const Buffer &data) {
        // rewind
        fseek(mFile, 0, SEEK_SET);

        // write data to file
        if (data.size() != fwrite(data.const_data(), 1, data.size(), mFile))
            throw cryptosqlite_exception("Failed to write keyfile");

        // write to disk
        fflush(mFile);

        // mark non-empty
        mEmpty = false;
    }

    void readFile(Buffer &contents) {
        // seek to end to tell size
        fseek(mFile, 0, SEEK_END);

        // tell size
        long fsizel = ftell(mFile);

        if (fsizel < 0)
            throw cryptosqlite_exception("ftell failed");

        auto fsize = static_cast<uint32_t>(fsizel);

        // rewind <<
        fseek(mFile, 0, SEEK_SET);

        // create and pre-pad buffer to file size
        contents.padd(fsize, 0);

        // read entire file into buffer
        if (fsize != fread(contents.data(), 1, fsize, mFile))
            throw cryptosqlite_exception("File could not be read");
    }

protected:
    FILE *mFile;
    bool mEmpty = false;
};

#endif //CRYPTOSQLITE_KEYFILE_H
