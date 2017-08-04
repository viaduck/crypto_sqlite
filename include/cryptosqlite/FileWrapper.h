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

        if (fsizel < 0 || fsizel > std::numeric_limits<uint32_t>::max())
            throw cryptosqlite_exception("ftell failed");

        uint32_t fsize = static_cast<uint32_t>(fsizel);

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
