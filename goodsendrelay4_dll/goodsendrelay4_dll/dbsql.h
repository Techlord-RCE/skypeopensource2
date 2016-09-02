#include <stdio.h>

#include <stdlib.h>

#include "db/sqlite3.h"

struct test_s {
    unsigned int global_table_exist;
    sqlite3 *db;
};
