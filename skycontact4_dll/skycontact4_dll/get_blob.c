// get_blob.c
//

#include "short_types.h"

extern int flag_auth_fail;
extern int flag_blob_04_35;
extern int flag_contacts_remain;
extern int flag_commands_remain;

extern char REMOTE_INDEXBUF[0x1000];
extern int REMOTE_INDEXBUF_LEN;



//
// 03-34 contact entry name blob
//
int get_03_34_blob(char *membuf, int membuf_len, char *output){
	int ret;
    u8 remote_chatstring[0x100];
    int remote_chatstring_len;

    remote_chatstring_len = 0;

	printf("Looking for 03-34 (contact name) blob...\n");
	ret = main_unpack_checkblob(membuf, membuf_len, 0x03, 0x34);
	if (ret == 1) {
		printf("BLOB found!\n");
		ret = main_unpack_getbuf (membuf, membuf_len, remote_chatstring, &remote_chatstring_len, 0x03, 0x34);
        //remote_chatstring[remote_chatstring_len]=0;
		printf("contactlist_name: %s\n",remote_chatstring);
		printf("contactlist_name_len: %d bytes\n", remote_chatstring_len);
        memcpy(output, remote_chatstring, remote_chatstring_len);

        flag_contacts_remain--;
		printf("flag_contacts_remain: %d\n", flag_contacts_remain);
	};

	return remote_chatstring_len;
};


//
// 04-33 contact entry cert blob
//
int get_04_33_blob(u8 *buf, int len, u8 *membuf, int *membuf_len) {
	int ret;

	printf("Looking for 04-33 blob...\n");
	ret = main_unpack_checkblob(buf, len, 0x04, 0x33);
	if (ret == 1){
		printf("BLOB found!\n");
		main_unpack_getbuf(buf, len, membuf, membuf_len, 0x04, 0x33);
		if (membuf_len<=0) {
			printf("unpack_getbuf size error\n");
			return -1;
		};
		printf("MEMBUF_LEN: %d bytes\n", *membuf_len);
		show_memory(membuf, *membuf_len, "MEMBUF");
	};

	return 0;
};


//
// 00-02 pkt_id count
//
int get_00_02_blob(u8 *buf, int buf_len, int *pkt_id){
	int ret;
	unsigned long data_int;

	printf("Looking for 00-02 blob...\n");
	ret = main_unpack_checkblob(buf, buf_len, 0x00, 0x02);
	if (ret == 1){
		printf("BLOB found!\n");
		main_unpack_getobj00(buf, buf_len, &data_int, 0x00, 0x02);
		printf("00-02: 0x%08X\n", data_int);
		*pkt_id = data_int;

        // some kind of cmd ack pkt, not actual command reply
        if (*pkt_id != 0x03) {
            flag_commands_remain--;
    		printf("flag_commands_remain: %d\n", flag_commands_remain);
        };
	};

	return 0;
};


//
// 00-01 error code check
//
int get_00_01_blob(u8 *buf, int buf_len, int *pkt_id){
	int ret;
	unsigned long data_int;

	printf("Looking for 00-01 blob...\n");
	ret = main_unpack_checkblob(buf, buf_len, 0x00, 0x01);
	if (ret == 1){
		printf("BLOB found!\n");
		main_unpack_getobj00(buf, buf_len, &data_int, 0x00, 0x01);
		printf("00-01: 0x%08X\n", data_int);
		*pkt_id = data_int;

        // auth error code
        if (*pkt_id == 0x20D1) {
            flag_auth_fail = 1;
    		printf("flag_auth_fail: %d\n", flag_auth_fail);
        };
	};

	return 0;
};


int get_04_35_blob(u8 *buf, int len, u8 *membuf, int *membuf_len) {
	int ret;

	printf("Looking for 04-35 blob...\n");
	ret = main_unpack_checkblob(buf, len, 0x04, 0x35);
	if (ret == 1){
		printf("BLOB found!\n");
		main_unpack_getbuf(buf, len, membuf, membuf_len, 0x04, 0x35);
		if (membuf_len<=0) {
			printf("unpack_getbuf size error\n");
			return -1;
		};
		printf("MEMBUF_LEN: %d bytes\n", *membuf_len);
		show_memory(membuf, *membuf_len, "MEMBUF");

        flag_blob_04_35 = 1;

	} else {
		//printf("04-35 blob not found\n");
		//return -1;
	};

	return 0;
};

