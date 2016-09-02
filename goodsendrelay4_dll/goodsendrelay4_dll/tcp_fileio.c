//
// for fileio operations
//

#include <stdio.h>
#include <stdlib.h>

#include <fcntl.h>
#include <io.h>

#include <string.h>
#include <windows.h>


#include "short_types.h"

extern u8 CHAT_STRING[0x100];
extern u8 REMOTE_NAME[0x100];


int do_mkdir() {
    char sdir[0x1000];

    memset(sdir, 0x00, 0x1000);

    sprintf(sdir, "./%s/", REMOTE_NAME);
    mkdir(sdir);

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
	fp=fopen(fpath, "a");
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

	fp = fopen(fpath, "r");
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

