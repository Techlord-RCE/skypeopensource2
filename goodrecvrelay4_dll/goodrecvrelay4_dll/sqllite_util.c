//
// create function
//
#include <stdio.h>
#include <stdlib.h>

#include "db/sqlite3.h"
#include "dbsql.h"


//
// do dbn check and init tables if need
//
int init_tables(struct test_s *gptr) {
    int ret;

    ret = 1;
    if (check_table_not_exist(gptr, "Messages")) {
    	ret = do_msgtable_create(gptr);
        if (ret < 0) { 
            do_dbclose(gptr);
            return -1; 
        };
    };

    if (check_table_not_exist(gptr, "Chats")) {
        ret = do_chattable_create(gptr);
        if (ret < 0) { 
            do_dbclose(gptr);
            return -1; 
        };
    };

    return ret;
};


//
// sqllite_open.c 
//
int do_dbopen(struct test_s *gptr) {
    int  rc;

    rc = sqlite3_open("main.db", &gptr->db);
    if( rc ){
        debuglog("Can't open database: %s\n", sqlite3_errmsg(gptr->db));
        return -1;
    } else {
        debuglog("Opened database successfully\n");
    };

    if (1) {
        debuglog("gptr->db = 0x%08X\n", gptr->db);
    };

    return 1;
};


int do_dbclose(struct test_s *gptr) {

   sqlite3_close(gptr->db);

   return 1;
};


//
// sqllite_exists.c 
//
int callback_exist(struct test_s *gptr, int argc, char **argv, char **azColName){
    int i;
    int sql_select_debug;

    sql_select_debug = 1;
    if (sql_select_debug) {
        for(i=0; i<argc; i++){
            debuglog("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
        }
        debuglog("\n");
    };

    i = 0;
    gptr->global_table_exist = atoi(argv[i]);

    // must return 0 by lib definition
    return 0;
};


int check_table_not_exist(struct test_s *gptr, char *tablename) {
    char *err_msg;
    int rc;
    char sql[0x1000];

    rc = 0;
    err_msg = NULL;
    
    sprintf(sql,"SELECT count(*) FROM sqlite_master WHERE type='table' AND name='%s'", tablename);

    gptr->global_table_exist = 0;

    if (0) {
        debuglog("sql = %s\n", sql);
        debuglog("gptr->db = 0x%08X\n", gptr->db);
    };

    rc = sqlite3_exec(gptr->db, sql, callback_exist, gptr, &err_msg);

    if (0) {
        debuglog("rc = %d\n", rc);
    };
                    
    if (rc != SQLITE_OK ) {
        debuglog("Failed to select data\n");
        debuglog("SQL error: %s\n", err_msg);
        debuglog("SQL error: %s\n", err_msg);
        sqlite3_free(err_msg);
    };

	debuglog("gptr->global_table_exist = %d\n", gptr->global_table_exist);

	if (gptr->global_table_exist == 0) {
        debuglog("No table found\n");
		return 1;
    } else {
        debuglog("Table %s already found\n", tablename);
    };

    return 0;
};


//
// sqllite_insert.c 
//


//
// Deleting msg by id
//
int sql_delete_msg(struct test_s *gptr, int row_id) {
    char *err_msg = 0;
    int rc;		
	char sql[0x1000];
    int last_id;

    sprintf(sql, "DELETE FROM Messages WHERE ID = %d", row_id);

    if (1) {
        debuglog("gptr->db = 0x%08X\n", gptr->db);
        debuglog("sql = %s\n", sql);
    };

    rc = sqlite3_exec(gptr->db, sql, 0, 0, &err_msg);
    
    if (rc != SQLITE_OK ) {
        debuglog("SQL error: %s\n", err_msg);
        sqlite3_free(err_msg);        
        return -1;
    };
    
    return 1;
};


//
// Updating local_header_id on msg
//
int sql_update_msg_localheader_crc(struct test_s *gptr, char *chatstring, 
        unsigned int local_header_id, unsigned int header_id_crc, unsigned int remote_header_id, 
        char *message) {

    char *err_msg = 0;
    int rc;		
	char sql[0x1000];
    int last_id;

    sprintf(sql, "UPDATE Messages SET local_header_id = %u, header_id_crc = %u WHERE chatstring = '%s' AND remote_header_id = %u",
            local_header_id, header_id_crc, chatstring, remote_header_id);

    if (1) {
        debuglog("gptr->db = 0x%08X\n", gptr->db);
        debuglog("sql = %s\n", sql);
    };

    rc = sqlite3_exec(gptr->db, sql, 0, 0, &err_msg);
    
    if (rc != SQLITE_OK ) {
        debuglog("SQL error: %s\n", err_msg);
        sqlite3_free(err_msg);        
        return -1;
    };
    
    return 1;
};


//
// Updating remote_header_id and crc on msg by local_header_id
//
int sql_update_msg_remoteheader_crc(struct test_s *gptr, char *chatstring, 
        unsigned int local_header_id, unsigned int header_id_crc, unsigned int remote_header_id, 
        char *message) {

    char *err_msg = 0;
    int rc;		
	char sql[0x1000];
    int last_id;

    sprintf(sql, "UPDATE Messages SET remote_header_id = %u, header_id_crc = %u WHERE chatstring = '%s' AND local_header_id = %u", 
            remote_header_id, header_id_crc, chatstring, local_header_id);

    if (1) {
        debuglog("gptr->db = 0x%08X\n", gptr->db);
        debuglog("sql = %s\n", sql);
    };

    rc = sqlite3_exec(gptr->db, sql, 0, 0, &err_msg);
    
    if (rc != SQLITE_OK ) {
        debuglog("SQL error: %s\n", err_msg);
        sqlite3_free(err_msg);        
        return -1;
    };
    
    return 1;
};


//
// Updating remote_header_id on msg by local_header_id
//
int sql_update_msg_remoteheader(struct test_s *gptr, char *chatstring, 
        unsigned int local_header_id, unsigned int header_id_crc, unsigned int remote_header_id, 
        char *message) {

    char *err_msg = 0;
    int rc;		
	char sql[0x1000];
    int last_id;

    sprintf(sql, "UPDATE Messages SET remote_header_id = %u WHERE chatstring = '%s' AND local_header_id = %u AND header_id_crc = %u", 
            remote_header_id, chatstring, local_header_id, header_id_crc);

    if (1) {
        debuglog("gptr->db = 0x%08X\n", gptr->db);
        debuglog("sql = %s\n", sql);
    };

    rc = sqlite3_exec(gptr->db, sql, 0, 0, &err_msg);
    
    if (rc != SQLITE_OK ) {
        debuglog("SQL error: %s\n", err_msg);
        sqlite3_free(err_msg);        
        return -1;
    };
    
    return 1;
};


//
// Adding msg with headers
//
int sql_save_msg_with_headers(struct test_s *gptr, 
        char *chatstring, char *remotename, char *localname,
        unsigned int local_header_id, unsigned int header_id_crc, unsigned int remote_header_id, 
        char *message, char *author, int is_service) {

    char *err_msg = 0;
    int rc;		
	char sql[0x1000];
    int last_id;

    sprintf(sql, "INSERT INTO Messages (chatstring, localname, remotename, local_header_id, header_id_crc, remote_header_id, message, author, is_service, createtime) VALUES('%s','%s','%s', %u, %u, %u, '%s', '%s', %d, strftime(\'%%s\', \'now\') )", 
            chatstring, localname, remotename, 
            local_header_id, header_id_crc, remote_header_id, message,
            author, is_service);

    if (1) {
        debuglog("gptr->db = 0x%08X\n", gptr->db);
        debuglog("sql = %s\n", sql);
    };

    rc = sqlite3_exec(gptr->db, sql, 0, 0, &err_msg);
    
    if (rc != SQLITE_OK ) {
        debuglog("SQL error: %s\n", err_msg);
        sqlite3_free(err_msg);        
        return -1;
    };
    
	// 'sqlite3_int64' to 'int', possible loss of data
    last_id = sqlite3_last_insert_rowid(gptr->db);
    debuglog("The last Id of the inserted row is %d\n", last_id);

    return last_id;
};


int sql_save_chatstring(struct test_s *gptr, char *chatstring, char *remotename,
                                            char *localname) {
    char *err_msg = 0;
    int rc;		
	char sql[0x1000];

    sprintf(sql, "INSERT INTO Chats (chatstring, remotename, localname, createtime) VALUES('%s','%s','%s', strftime(\'%%s\', \'now\') )",
            chatstring, remotename, localname);

    debuglog("sql = %s\n", sql);

    rc = sqlite3_exec(gptr->db, sql, 0, 0, &err_msg);
    
    if (rc != SQLITE_OK ) {
        debuglog("SQL error: %s\n", err_msg);
        sqlite3_free(err_msg);        
        return -1;
    };
    
    return 1;
};


//
// select
//

int sql_load_headers(struct test_s *gptr, char *chatstring, 
        char *remotename, char *localname, unsigned int *local_header_id, 
        unsigned int *header_id_crc, unsigned int *remote_header_id) {

    int ret;
    char *err_msg = 0;
    sqlite3_stmt *res;
    int rc;
    char sql[0x1000];


    sprintf(sql, "SELECT local_header_id, header_id_crc, remote_header_id FROM Messages WHERE chatstring = ? AND remotename = ? AND localname = ? ORDER BY ID DESC",
            chatstring, remotename, localname);

    debuglog("sql = %s\n", sql);

    rc = sqlite3_prepare_v2(gptr->db, sql, -1, &res, 0);
    
    // prepare statement
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(res, 1, chatstring, -1, SQLITE_STATIC);
        sqlite3_bind_text(res, 2, remotename, -1, SQLITE_STATIC);
        sqlite3_bind_text(res, 3, localname,  -1, SQLITE_STATIC);
    } else {
        debuglog("Failed to execute statement: %s\n", sqlite3_errmsg(gptr->db));
    }

    // do actual query
    ret = sqlite3_step(res);
    if (ret == SQLITE_ROW) {

        debuglog("local_header_id = %u\n", sqlite3_column_int(res, 0));
        *local_header_id = sqlite3_column_int(res, 0);

        debuglog("header_id_crc = %u\n", sqlite3_column_int(res, 1));
        *header_id_crc = sqlite3_column_int(res, 1);

        debuglog("remote_header_id = %u\n", sqlite3_column_int(res, 2));
        *remote_header_id = sqlite3_column_int(res, 2);

    } else {

        if (ret == SQLITE_DONE) {
            debuglog("No records found.\n");
            return 0;
        } else {
            debuglog("Unknown error on sqlite3_step\n");
            debuglog("ret = %d\n", ret);
            return -1;
        };

	};

    sqlite3_finalize(res);
    
    return 1;
}


int sql_load_chatstring(struct test_s *gptr, char *chatstring, char *remotename,
                                            char *localname) {
    int ret;
    char *err_msg = 0;
    sqlite3_stmt *res;
    int rc;

    char *sql = "SELECT chatstring FROM Chats WHERE remotename = ? and localname = ?";

    rc = sqlite3_prepare_v2(gptr->db, sql, -1, &res, 0);
    
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(res, 1, remotename, -1, SQLITE_STATIC);
        sqlite3_bind_text(res, 2, localname, -1, SQLITE_STATIC);
    } else {
        debuglog("Failed to execute statement: %s\n", sqlite3_errmsg(gptr->db));
    }

    ret = sqlite3_step(res);
    if (ret == SQLITE_ROW) {
        debuglog("chatstring = %s\n", sqlite3_column_text(res, 0));
        sprintf(chatstring, "%s", sqlite3_column_text(res, 0));
    } else {

        if (ret == SQLITE_DONE) {
            debuglog("No records found.\n");
            return 0;
        } else {
            debuglog("Unknown error on sqlite3_step\n");
            debuglog("ret = %d\n", ret);
            return -1;
        };

	};

    sqlite3_finalize(res);
    
    return 1;
}


//
// sqllite_create.c 
//
int callback_create(void *data, int argc, char **argv, char **azColName) {
   int i;

   debuglog("%s: ", (char*)data);
   for(i=0; i<argc; i++){
      debuglog("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
   }
   debuglog("\n");

   return 0;
};

int do_msgtable_create(struct test_s *gptr) {
   char *zErrMsg = 0;
   char *sql;
   int rc;


   sql = "CREATE TABLE Messages ("  \
         "ID						 INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL," \
         "chatstring		         CHAR(255)    NOT NULL," \
         "localname	    	         CHAR(255)    NOT NULL," \
         "remotename		         CHAR(255)    NOT NULL," \
         "local_header_id            INT      NOT NULL," \
         "header_id_crc				 INT	  NOT NULL," \
         "remote_header_id           INT      NOT NULL," \
         "message					 TEXT     NOT NULL," \
         "author    				 TEXT     NOT NULL," \
         "is_service    			 INT	  NOT NULL," \
         "createtime		         INTEGER           " \
         ")";


   rc = sqlite3_exec(gptr->db, sql, callback_create, 0, &zErrMsg);
   
   if( rc != SQLITE_OK ){
		debuglog("SQL error: %s\n", zErrMsg);
		sqlite3_free(zErrMsg);
   }else{
		debuglog("Table created successfully\n");
   }
   
   return 1;
};


int do_chattable_create(struct test_s *gptr) {
   char *zErrMsg = 0;
   char *sql;
   int  rc;

   sql = "CREATE TABLE Chats ("  \
         "ID						 INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL," \
         "chatstring		         CHAR(255)    NOT NULL," \
         "localname 		         CHAR(255)    NOT NULL," \
         "remotename                 CHAR(255)    NOT NULL," \
         "createtime		         INTEGER               " \
         ")";

   rc = sqlite3_exec(gptr->db, sql, callback_create, 0, &zErrMsg);
   
   if( rc != SQLITE_OK ){
		debuglog("SQL error: %s\n", zErrMsg);
		sqlite3_free(zErrMsg);
   }else{
		debuglog("Table created successfully\n");
   }
   
   return 1;
};

