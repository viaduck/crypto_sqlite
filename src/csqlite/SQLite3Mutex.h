/*
 * Copyright (C) 2020 The ViaDuck Project
 *
 * This file is part of CryptoSQLite.
 *
 * CryptoSQLite is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * CryptoSQLite is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with CryptoSQLite.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef CRYPTOSQLITE_SQLITE3MUTEX_H
#define CRYPTOSQLITE_SQLITE3MUTEX_H

class SQLite3Mutex {
public:
    SQLite3Mutex() : mMutex(sqlite3_mutex_alloc(SQLITE_MUTEX_RECURSIVE)), mOwned(true) {
        // TODO: errorhandling if !mMutex
    }

    SQLite3Mutex(sqlite3_mutex *mutex) : mMutex(mutex) { }

    ~SQLite3Mutex() {
        if (mOwned)
            sqlite3_mutex_free(mMutex);
    }

    void lock() {
        sqlite3_mutex_enter(mMutex);
    }

    void unlock() {
        sqlite3_mutex_leave(mMutex);
    }

protected:
    sqlite3_mutex *mMutex;
    bool mOwned = false;
};

class SQLite3LockGuard {
public:
    explicit SQLite3LockGuard(SQLite3Mutex &mutex) : mMutex(mutex) {
        mMutex.lock();
    }

    ~SQLite3LockGuard() {
        mMutex.unlock();
    }

protected:
    SQLite3Mutex &mMutex;
};

#endif //CRYPTOSQLITE_SQLITE3MUTEX_H
