//
// main.c code for sqllite3 probe
//
#include <stdio.h>
#include <stdlib.h>

#include "db/sqlite3.h"
#include "dbsql.h"


//
// Update localheader in db
//
int update_lh_crc_to_db(char *chatstring, 
                    unsigned int local_header_id, unsigned int header_id_crc, 
                    unsigned int remote_header_id) {
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
    ret = sql_update_msg_localheader_crc(&gptr, chatstring,
                    local_header_id, header_id_crc, remote_header_id);
    debuglog("sql_update_msg_localheader_crc ret: %d\n", ret); 
    if (ret < 0 ) { 
        do_dbclose(&gptr);
        return ret; 
    };

    // close db
    do_dbclose(&gptr);

	return ret;
};


//
// do load last localheader
//
int load_headers_from_db(char *chatstring, char *remotename, char *localname,
                unsigned int *local_header_id, unsigned int *header_id_crc, 
                unsigned int *remote_header_id) {
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

    // load data from table
    ret = sql_load_headers(&gptr, chatstring, remotename, localname,
                    local_header_id, header_id_crc, remote_header_id);
    debuglog("sql_load_headers ret: %d\n", ret); 
    if (ret < 0 ) { 
        do_dbclose(&gptr);
        return ret; 
    };

    // close db
    do_dbclose(&gptr);

	return ret;
};


//
// remove all added rows if sending fail
//
int remove_from_db(int row_id) {
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
    ret = sql_delete_msg(&gptr, row_id);
    debuglog("sql_delete_msg ret: %d\n", ret); 
    if (ret < 0 ) { 
        do_dbclose(&gptr);
        return ret; 
    };

    // close db
    do_dbclose(&gptr);

	return ret;
};


int update_rh_crc_to_db(char *chatstring, 
                    unsigned int local_header_id, unsigned int header_id_crc, 
                    unsigned int remote_header_id) {
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
    ret = sql_update_msg_remoteheader_crc(&gptr, chatstring,
                    local_header_id, header_id_crc, remote_header_id);
    debuglog("sql_update_msg_remoteheader ret: %d\n", ret); 
    if (ret < 0 ) { 
        do_dbclose(&gptr);
        return ret; 
    };

    // close db
    do_dbclose(&gptr);

	return ret;
};


int update_rh_to_db(char *chatstring, 
                    unsigned int local_header_id, unsigned int header_id_crc, 
                    unsigned int remote_header_id) {
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
    ret = sql_update_msg_remoteheader(&gptr, chatstring,
                    local_header_id, header_id_crc, remote_header_id);
    debuglog("sql_update_msg_remoteheader ret: %d\n", ret); 
    if (ret < 0 ) { 
        do_dbclose(&gptr);
        return ret; 
    };

    // close db
    do_dbclose(&gptr);

	return ret;
};


int insert_to_db(char *chatstring, char *remotename, char *localname,
                unsigned int local_header_id, unsigned int header_id_crc, unsigned int remote_header_id,
                char *message, char *author, int is_service) {
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
    ret = sql_save_msg_with_headers(&gptr, chatstring, remotename, localname,
                    local_header_id, header_id_crc, remote_header_id, 
                    message, author, is_service);
    debuglog("sql_save_msg_with_headers ret: %d\n", ret); 
    if (ret < 0 ) { 
        do_dbclose(&gptr);
        return ret; 
    };

    // close db
    do_dbclose(&gptr);

	return ret;
};


//
// main function called from goodsendrelay
//
int save_to_db(char *chatstring, char *remotename, char *localname) {
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
	ret = sql_save_chatstring(&gptr, chatstring, remotename, localname);
    debuglog("sql_save_chatstring ret: %d\n", ret); 
    if (ret < 0 ) { 
        do_dbclose(&gptr);
        return ret; 
    };

    // close db
    do_dbclose(&gptr);

	return ret;
};


//
// main function called from goodsendrelay
//
// remotename, localname - input
// chatstring - output
//
int load_from_db(char *chatstring, char *remotename, char *localname) {
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
	ret = sql_load_chatstring(&gptr, chatstring, remotename, localname);
    debuglog("sql_load_chatstring ret: %d\n", ret); 
    if (ret < 0 ) { 
        do_dbclose(&gptr);
        return ret; 
    };

    // close db
    do_dbclose(&gptr);

	return ret;
};

