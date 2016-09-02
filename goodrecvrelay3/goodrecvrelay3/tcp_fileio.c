#include <stdio.h>
#include <stdlib.h>

#include <fcntl.h>
#include <io.h>

#include "short_types.h"

extern u8 CHAT_STRING[0x100];
extern u8 REMOTE_CHAT_STRING[0x100];
extern u8 REMOTE_NAME[0x100];


int do_mkdir() {
    char sdir[0x1000];

    memset(sdir, 0x00, 0x1000);

    sprintf(sdir, "./%s/", REMOTE_NAME);
    mkdir(sdir);

    return 0;
};



//
// save_good and load from file functions
//


//
// save REMOTE chatstring for later usage
//
unsigned int save_good_remote_chatstring() {
	FILE *fp;
    char fpath[0x1000];

    do_mkdir();

	debuglog("Writing inited REMOTE CHAT STRING to file...\n");

    sprintf(fpath, "./%s/_good_chat_session.txt", REMOTE_NAME);
	fp=fopen(fpath, "w");
	if (fp==NULL){
		debuglog("logfile creation error\n");
		return -1;
	};
	fprintf(fp,"%s\n",REMOTE_CHAT_STRING);
	fclose(fp);

	debuglog("Done.\n");
    
    return 0;
};


//
// save success chatstring for later usage
//
unsigned int save_good_chatstring() {
	FILE *fp;
    char fpath[0x1000];

    do_mkdir();

	debuglog("Writing inited CHAT STRING to file...\n");

    sprintf(fpath, "./%s/_good_chat_session.txt", REMOTE_NAME);
	fp=fopen(fpath, "w");
	if (fp==NULL){
		debuglog("logfile creation error\n");
		return -1;
	};
	fprintf(fp,"%s\n",CHAT_STRING);
	fclose(fp);

	debuglog("Done.\n");
    
    return 0;
};


int load_chatstring_from_file(char *tmpbuf) {
	FILE *fp;
	char str_buf[4096];
	int ret;
	int len;
    char fpath[0x1000];


    len = 0;
    memset(str_buf,0,sizeof(str_buf));

    do_mkdir();

    sprintf(fpath, "./%s/_good_chat_session.txt", REMOTE_NAME);
	fp=fopen(fpath, "r");
	if (fp == NULL){
		debuglog("Open failed on _good_chat_session.txt\n");
		debuglog("So needed init new session?\n");
        return 0;
	};

	while(!feof(fp)){
		fgets(str_buf, sizeof(str_buf), fp);
        len = strlen(str_buf);
        if (len > 0) {
            // remove newline (len-1)
            memcpy(tmpbuf,str_buf,len-1);
		} else {
            debuglog("CHAT STRING LOAD FILE FORMAT ERROR, do return...\n");
            debuglog("len: %d\n", len);
            debuglog("str_buf: %s\n", str_buf);
            return -1;
        };
	};

	fclose(fp);

	return len;
};


///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////



//
// save success LASTSYNC for later usage
//
int save_good_lastsync(unsigned int header_id, unsigned int header_crc) {
	FILE *fp;
    char fpath[0x1000];

    do_mkdir();

	debuglog("Writing inited LASTSYNC to file...\n");

    sprintf(fpath, "./%s/_lastsync.txt", REMOTE_NAME);
	fp=fopen(fpath, "w");
	if (fp==NULL){
		debuglog("logfile creation error\n");
		return -1;
	};
	fprintf(fp,"%08X\n",header_id);
	fprintf(fp,"%08X\n",header_crc);
	fclose(fp);

	debuglog("Done.\n");
    
    return 0;
};


int load_lastsync_from_file(unsigned int *header_id, unsigned int *header_crc) {
	FILE *fp;
	char str_buf[4096];
	char tmpbuf[4096];
	int ret;
	int len = 0;
    char fpath[0x1000];

    memset(str_buf,0,sizeof(str_buf));

    do_mkdir();

    sprintf(fpath, "./%s/_lastsync.txt", REMOTE_NAME);
	fp=fopen(fpath, "r");
	if (fp == NULL){
		debuglog("Open failed on _lastsync.txt\n");
		debuglog("So needed init new session?\n");
        return -1;
	};

	//line1

	fgets(str_buf, sizeof(str_buf), fp);
    len = strlen(str_buf);
    if (len > 0) {
		// remove newline (len-1)
		memcpy(tmpbuf,str_buf,len-1);
		//*header_id = atoi(tmpbuf);
		sscanf(tmpbuf,"%X", header_id);
	} else {
		debuglog("LASTSYNC LOAD FILE FORMAT ERROR, do return...\n");
		debuglog("len: %d\n", len);
		debuglog("str_buf: %s\n", str_buf);
		return -1;
	};

	//line2

	fgets(str_buf, sizeof(str_buf), fp);
    len = strlen(str_buf);
    if (len > 0) {
		// remove newline (len-1)
		memcpy(tmpbuf,str_buf,len-1);
		//*header_crc = atoi(tmpbuf);
		sscanf(tmpbuf,"%X", header_crc);
	} else {
		debuglog("LASTSYNC LOAD FILE FORMAT ERROR, do return...\n");
		debuglog("len: %d\n", len);
		debuglog("str_buf: %s\n", str_buf);
		return -1;
	};

	fclose(fp);

	debuglog("loaded header_id = 0x%08X\n", *header_id);
	debuglog("loaded header_crc = 0x%08X\n", *header_crc);

	return 0;
};


///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////


//
// save success recv in msgcount for later usage
//
int save_msgcount(int msgcount) {
	FILE *fp;
    char fpath[0x1000];

    do_mkdir();

	debuglog("Writing inited msgcount to file...\n");

    sprintf(fpath, "./%s/_msgcount.txt", REMOTE_NAME);
	fp=fopen(fpath, "w");
	if (fp==NULL){
		debuglog("logfile creation error\n");
		return -1;
	};
	fprintf(fp,"%d\n",msgcount);
	fclose(fp);

	debuglog("Done.\n");
    
    return 0;
};


int load_msgcount_from_file(int *msgcount) {
	FILE *fp;
	char str_buf[4096];
	char tmpbuf[4096];
	int ret;
	int len = 0;
    char fpath[0x1000];

    memset(str_buf,0,sizeof(str_buf));

    do_mkdir();

    sprintf(fpath, "./%s/_msgcount.txt", REMOTE_NAME);
	fp=fopen(fpath, "r");
	if (fp == NULL){
		debuglog("Open failed on _msgcount.txt\n");
		debuglog("So needed init new session?\n");
        return -1;
	};

	fgets(str_buf, sizeof(str_buf), fp);
    len = strlen(str_buf);
    if (len > 0) {
		// remove newline (len-1)
		memcpy(tmpbuf,str_buf,len-1);
		*msgcount = atoi(tmpbuf);
	} else {
		debuglog("The msgcount LOAD FILE FORMAT ERROR, do return...\n");
		debuglog("len: %d\n", len);
		debuglog("str_buf: %s\n", str_buf);
		return -1;
	};

	fclose(fp);

	debuglog("loaded msgcount = %d\n", *msgcount);

	return 0;
};


///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////


//
// save good LOCALHEADERS for later usage
//
int save_good_localheaders(unsigned int header_id, unsigned int header_crc) {
	FILE *fp;
    char fpath[0x1000];

    do_mkdir();

	debuglog("Writing inited LOCALHEADERS to file...\n");

    sprintf(fpath, "./%s/_localheaders.txt", REMOTE_NAME);
	fp=fopen(fpath, "w");
	if (fp==NULL){
		debuglog("logfile creation error\n");
		return -1;
	};
	fprintf(fp,"%08X\n",header_id);
	fprintf(fp,"%08X\n",header_crc);
	fclose(fp);

	debuglog("Done.\n");
    
    return 0;
};


int load_localheaders_from_file(unsigned int *header_id, unsigned int *header_crc) {
	FILE *fp;
	char str_buf[4096];
	char tmpbuf[4096];
	int ret;
	int len = 0;
    char fpath[0x1000];

    do_mkdir();

    memset(str_buf,0,sizeof(str_buf));

    sprintf(fpath, "./%s/_localheaders.txt", REMOTE_NAME);
	fp=fopen(fpath, "r");
	if (fp == NULL){
		debuglog("Open failed on _localheaders.txt\n");
		debuglog("So needed init new session?\n");
        return -1;
	};

	//line1

	fgets(str_buf, sizeof(str_buf), fp);
    len = strlen(str_buf);
    if (len > 0) {
		// remove newline (len-1)
		memcpy(tmpbuf,str_buf,len-1);
		//*header_id = atoi(tmpbuf);
		sscanf(tmpbuf,"%X", header_id);
	} else {
		debuglog("LOCALHEADERS LOAD FILE FORMAT ERROR, do return...\n");
		debuglog("len: %d\n", len);
		debuglog("str_buf: %s\n", str_buf);
		return -1;
	};

	//line2

	fgets(str_buf, sizeof(str_buf), fp);
    len = strlen(str_buf);
    if (len > 0) {
		// remove newline (len-1)
		memcpy(tmpbuf,str_buf,len-1);
		//*header_crc = atoi(tmpbuf);
		sscanf(tmpbuf,"%X", header_crc);
	} else {
		debuglog("LOCALHEADERS LOAD FILE FORMAT ERROR, do return...\n");
		debuglog("len: %d\n", len);
		debuglog("str_buf: %s\n", str_buf);
		return -1;
	};

	fclose(fp);

	debuglog("loaded local header_id = 0x%08X\n", *header_id);
	debuglog("loaded local header_crc = 0x%08X\n", *header_crc);

	return 0;
};


///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////


//
// save REMOTE_MSG to file
//
int save_msg_tofile(char *msg) {
	FILE *fp;
    char fpath[0x1000];

    do_mkdir();

	debuglog("Writing inited REMOTE_MSG to file...\n");

    sprintf(fpath, "./%s/recv_msg.txt", REMOTE_NAME);
	fp=fopen(fpath, "a");
	if (fp==NULL){
		debuglog("logfile creation error\n");
		return -1;
	};
	fprintf(fp,"%s\n",msg);
	fclose(fp);

	debuglog("Done.\n");
    
    return 0;
};


int clear_msg_file() {
	FILE *fp;
    char fpath[0x1000];

    do_mkdir();

    sprintf(fpath, "./%s/recv_msg.txt", REMOTE_NAME);
	fp=fopen(fpath, "w");
	fclose(fp);

    return 0;
};

