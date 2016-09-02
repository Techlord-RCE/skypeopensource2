//
// main.c code for sqllite3 probe
//
#include <stdio.h>
#include <stdlib.h>

#include "db/sqlite3.h"
#include "dbsql.h"

//
// main function called from goodsendrelay
// localname -- input
// remotename -- input
// chat_history -- output
//
int load_chathistory_from_db(char *localname, char *remotename, char *chat_history) {
    int ret;
    struct test_s gptr;

    debuglog("SQLITE VERSION: %s\n", sqlite3_libversion()); 

    // open db even if not exists
    ret = do_dbopen(&gptr);
    debuglog("dbopen ret: %d\n", ret); 
    if (ret < 0 ) { 
        return ret; 
    };

    // creating tables if need
    ret = init_tables(&gptr);
    debuglog("init_tables ret: %d\n", ret); 
    if (ret < 0 ) { 
        do_dbclose(&gptr);
        return ret; 
    };

    // save data to table
	ret = sql_load_chathistory(&gptr, localname, remotename, chat_history);
    debuglog("sql_load_chathistory ret: %d\n", ret); 
    if (ret < 0 ) { 
        do_dbclose(&gptr);
        return ret; 
    };

    // close db
    do_dbclose(&gptr);

	return ret;
};

