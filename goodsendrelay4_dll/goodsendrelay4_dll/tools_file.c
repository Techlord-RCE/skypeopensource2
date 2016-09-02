//
// Tools for file logging
//

#include <stdio.h>
#include <stdlib.h>

#include <fcntl.h>
#include <io.h>

#include "short_types.h"


//
// do init files
//
int do_init_logfiles() {
    FILE *fp;

    fp=fopen("_mylog.txt","w");
    if (fp==NULL){
        debuglog("logfile creation error\n");
        return -10;
    };
    fclose(fp);

    fp=fopen("_pktlog.txt","w");
    if (fp==NULL){
        debuglog("logfile creation error\n");
        return -10;
    };
    fclose(fp);

    fp=fopen("_protolog.txt","w");
    if (fp==NULL){
        debuglog("logfile creation error\n");
        return -10;
    };
    fclose(fp);

    return 0;
};


//
// logging cmd packets separately
//
int do_pktlog_cmd(unsigned int cmd) {
    FILE *fp;

    fp=fopen("_pktlog.txt","a");
    if (fp==NULL){
        debuglog("logfile creation error\n");
        return -10;
    };

    fprintf(fp,"Found blob 00-01 in 6D --> 05-03 --> 04-04\n");
    fprintf(fp,"Chat CMD: 0x%02X\n\n\n", cmd);
    fclose(fp);

    return 0;
};


//
// logging A6 01 packets separately
//
int do_pktlog_A6_type(unsigned int data_A6_type) {
    FILE *fp;

    fp=fopen("_pktlog.txt","a");
    if (fp==NULL){
        debuglog("logfile creation error\n");
        return -10;
    };

	fprintf(fp,"RECV PKT TYPE: 0x%02X\n",data_A6_type);
    fclose(fp);

    return 0;
};


//
// log send and recv packets
//
int do_proto_log(u8 *pktbuf, u32 pktlen, char *header) {
	u8 membuf[0x10000];
	int membuf_len;
    char str[0x10000];
    int str_len;
    FILE *fp;
    int ret;

    str_len = 0x0;
    memset(str,0x00,sizeof(str));

    fp=fopen("_protolog.txt","a");
    if (fp==NULL){
        debuglog("logfile creation error\n");
        return -10;
    };

	main_unpack_log(pktbuf, pktlen, str, &str_len);

	fprintf(fp,"===\n");
	fprintf(fp,"PARAM %s\n", header);
	fprintf(fp,"===\n");
	fprintf(fp,"%s", str);
	fprintf(fp,"===\n");

	//debuglog("Looking for 04-04 blob...\n");
	ret = main_unpack_checkblob(pktbuf, pktlen, 0x04, 0x04);
	if (ret == 1){
		debuglog("BLOB found!\n");
		main_unpack_getbuf(pktbuf, pktlen, membuf, &membuf_len, 0x04, 0x04);
		if (membuf_len<=0) {
			debuglog("unpack_getbuf size error\n");
			return -1;
		};
		//debuglog("MEMBUF_LEN: %d bytes\n", membuf_len);
		//show_memory(membuf, membuf_len, "MEMBUF");

        str_len = 0x0;
        memset(str,0x00,sizeof(str));

    	main_unpack_log(membuf, membuf_len, str, &str_len);

    	fprintf(fp,"%s", str);
    	fprintf(fp,"===\n");
	};

    fclose(fp);
    
    return 0;
};


//
// log decoded data
//
int do_proto_log_cryptodecode(u8 *pktbuf, u32 pktlen, char *header) {

    recovery_signed_data(pktbuf, pktlen);

};
