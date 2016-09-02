//
// get blob data
//

#include <stdio.h>
#include <stdlib.h>

#include "short_types.h"

extern int main_unpack_checkblob (u8 *indata, u32 inlen, int type, int id);
extern int main_unpack_getbuf (u8 *indata, u32 inlen, u8 *membuf, int *membuf_len, int type, int id);
extern int main_unpack_getobj00 (u8 *indata, u32 inlen, u32 *data_int, int type, int id);

extern int show_memory(char *mem, int len, char *text);



int get_04_04_blob(u8 *buf, int len, u8 *membuf, int *membuf_len) {
	int ret;

	debuglog("Looking for 04-04 blob...\n");
	ret = main_unpack_checkblob(buf, len, 0x04, 0x04);
	if (ret == 1){
		debuglog("BLOB found!\n");
		main_unpack_getbuf(buf, len, membuf, membuf_len, 0x04, 0x04);
		if (membuf_len<=0) {
			debuglog("unpack_getbuf size error\n");
			return -1;
		};
		debuglog("MEMBUF_LEN: %d bytes\n", *membuf_len);
		show_memory(membuf, *membuf_len, "MEMBUF");

	} else {
		debuglog("04-04 blob not found\n");
		return -1;
	};

	return 0;
};



//
// 04-03 signed block
//
int get_04_03_blob(u8 *buf, int len, u8 *membuf, int *membuf_len) {
	int ret;

	debuglog("Looking for 04-03 blob...\n");
	ret = main_unpack_checkblob(buf, len, 0x04, 0x03);
	if (ret == 1){
		debuglog("BLOB found!\n");
		main_unpack_getbuf(buf, len, membuf, membuf_len, 0x04, 0x03);
		if (membuf_len<=0) {
			debuglog("unpack_getbuf size error\n");
			return -1;
		};
		debuglog("MEMBUF_LEN: %d bytes\n", *membuf_len);
		show_memory(membuf, *membuf_len, "MEMBUF");

	} else {
		debuglog("04-03 blob not found\n");
		return -1;
	};

	return 0;
};


//
// 00-01 chat command
//
int get_00_01_blob(u8 *buf, int buf_len, int *chat_cmd){
	int ret;
	unsigned long data_int;

	debuglog("Looking for 00-01 (remote cmd) blob...\n");
	ret = main_unpack_checkblob(buf, buf_len, 0x00, 0x01);
	if (ret == 1){
		debuglog("BLOB found!\n");
		main_unpack_getobj00(buf, buf_len, &data_int, 0x00, 0x01);
		debuglog("00-01 (CHAT CMD ID): 0x%08X\n", data_int);
		*chat_cmd = data_int;
	} else {
		debuglog("not found blob 00-01 in 6D --> 05-03 --> 04-04\n");
	};

	return 0;
};


//
// 00-02 (in 04-04 blob) UIC_CRC
//
int get_00_02_blob(u8 *buf, int buf_len, int *uic_crc){
	int ret;
	unsigned long data_int;

	debuglog("Looking for 00-02 (remote cmd) blob...\n");
	ret = main_unpack_checkblob(buf, buf_len, 0x00, 0x02);
	if (ret == 1){
		debuglog("BLOB found!\n");
		main_unpack_getobj00(buf, buf_len, &data_int, 0x00, 0x02);
		debuglog("00-02 (UIC CRC): 0x%08X\n", data_int);
		*uic_crc = data_int;
	} else {
		debuglog("not found blob 00-02 in 6D --> 05-03 --> 04-04\n");
	};

	return 0;
};


//
// 00-04 (in credentials) Expire Time
//
int get_00_04_blob(u8 *buf, int buf_len, int *expire_time){
	int ret;
	unsigned long data_int;

	debuglog("Looking for 00-04 blob...\n");
	ret = main_unpack_checkblob(buf, buf_len, 0x00, 0x04);
	if (ret == 1){
		debuglog("BLOB found!\n");
		main_unpack_getobj00(buf, buf_len, &data_int, 0x00, 0x04);
		debuglog("00-04 (Expire Time): 0x%08X\n", data_int);
		*expire_time = data_int;
	} else {
		debuglog("not found blob 00-04 in cert\n");
	};

	return 0;
};


//
// 00-09 (in credentials) Created Time
//
int get_00_09_blob(u8 *buf, int buf_len, int *created_time){
	int ret;
	unsigned long data_int;

	debuglog("Looking for 00-09 blob...\n");
	ret = main_unpack_checkblob(buf, buf_len, 0x00, 0x09);
	if (ret == 1){
		debuglog("BLOB found!\n");
		main_unpack_getobj00(buf, buf_len, &data_int, 0x00, 0x09);
		debuglog("00-09 (Created Time): 0x%08X\n", data_int);
		*created_time = data_int;
	} else {
		debuglog("not found blob 00-09 in cert\n");
	};

	return 0;
};


int get_03_02_blob(char *membuf, int membuf_len, char *output){
	int ret;
    u8 remote_chatstring[0x100];
    int remote_chatstring_len;

    remote_chatstring_len = 0;

	debuglog("Looking for 03-02 (remote chatstring) blob...\n");
	ret = main_unpack_checkblob(membuf, membuf_len, 0x03, 0x02);
	if (ret == 1) {
		debuglog("BLOB found!\n");
		ret = main_unpack_getbuf (membuf, membuf_len, remote_chatstring, &remote_chatstring_len, 0x03, 0x02);
		debuglog("remote_chatstring: %s\n",remote_chatstring);
		debuglog("remote_chatstring_len: %d bytes\n", remote_chatstring_len);
        memcpy(output, remote_chatstring, remote_chatstring_len);
	} else {
		debuglog("Not found blob 03-02 in 6D --> 05-03 --> 04-04\n");
		//return 1;
	};

	return remote_chatstring_len;
};

int get_00_0A_blob(char *membuf, int membuf_len){
	int data_int;
	int ret;

	data_int = 0;
	debuglog("Looking for 00-0A (remote header_id) blob...\n");
	ret = main_unpack_checkblob(membuf, membuf_len, 0x00, 0x0A);
	if (ret == 1){
		debuglog("BLOB found!\n");
		main_unpack_getobj00(membuf, membuf_len, &data_int, 0x00, 0x0A);
		debuglog("00-0A (remote HEADER_ID): 0x%08X\n", data_int);
		// maybe need change some global chat control state? or stage?
		//HEADER_ID = data_int;
		//debuglog("HEADER_ID: 0x%08X\n", HEADER_ID);
	} else {
		debuglog("not found blob 00-0A in 6D --> 05-03 --> 04-04\n");
		// blob not found
		// this is not "HEADER_ID" 6D packet...
		//return 1;
	};

	return data_int;
};


int get_00_0A_blob_last(char *membuf, int membuf_len){
	int data_int;
	int ret;

	data_int = 0;
	debuglog("Looking for 00-0A (remote header_id) blob...\n");
	ret = main_unpack_checkblob(membuf, membuf_len, 0x00, 0x0A);
	if (ret == 1){
		debuglog("BLOB found!\n");
		main_unpack_getobj00(membuf, membuf_len, &data_int, 0x00, 0x0A);
		debuglog("00-0A (remote HEADER_ID): 0x%08X\n", data_int);
	} else {
		debuglog("not found blob 00-0A in 6D --> 05-03 --> 04-04\n");
		//return 1;
	};

	return data_int;
};


int get_00_15_blob_last(char *membuf, int membuf_len){
	int data_int;
	int ret;

	data_int = 0;
	debuglog("Looking for 00-15 (remote header_id_crc) blob...\n");
	ret = main_unpack_checkblob(membuf, membuf_len, 0x00, 0x15);
	if (ret == 1) {
		debuglog("BLOB found!\n");
		main_unpack_getobj00(membuf, membuf_len, &data_int, 0x00, 0x15);
		debuglog("00-15 (remote HEADER_ID_CRC): 0x%08X\n", data_int);
	} else {
		debuglog("not found blob 00-15 in 6D --> 05-03 --> 04-04\n");
		//return 1;
	};

	return data_int;
};


int get_01_36_blob(char *membuf, int membuf_len){
	u8 rnd64bit[0x8];
    u8 data_64bit[0x08];
	int ret;
    int data_int;

	data_int = 0;
	debuglog("Looking for 01-36 (remote header_id) blob...\n");
	ret = main_unpack_checkblob(membuf, membuf_len, 0x01, 0x36);
	if (ret == 1){
		debuglog("BLOB found!\n");
		memset(data_64bit, 0, 0x08);
		main_unpack_getobj01(membuf, membuf_len, data_64bit, 0x01, 0x36);
		memcpy(rnd64bit, data_64bit+4, 4);
		memcpy(rnd64bit+4, data_64bit, 4);
		show_memory(rnd64bit, 8, "01-36 (remote HEADER_ID_CRC)");
	} else {
		debuglog("not found blob 01-36 in 6D --> 05-03 --> 04-04\n");
		//return 1;
	};

	return data_int;
};


//
// 00-05
//
int get_00_05_blob(u8 *buf, int buf_len){
	int ret;
	unsigned long data_int;

    data_int = 0;
	debuglog("Looking for 00-05 blob...\n");
	ret = main_unpack_checkblob(buf, buf_len, 0x00, 0x05);
	if (ret == 1){
		debuglog("BLOB found!\n");
		main_unpack_getobj00(buf, buf_len, &data_int, 0x00, 0x05);
		debuglog("00-05: 0x%08X\n", data_int);
	} else {
		debuglog("not found blob 00-05\n");
	};

	return data_int;
};


//
// 04-03 msg count calc
//
int get_04_03_blob_count(char *membuf, int membuf_len){
	int ret;
    int blobs_count;

    blobs_count = 0;

	debuglog("Looking for 04-03 (remote msg buf) blob...\n");
	ret = main_unpack_checkblob(membuf, membuf_len, 0x04, 0x03);
	if (ret == 1) {
		debuglog("BLOB found!\n");
		ret = main_unpack_getbuf_count(membuf, membuf_len, &blobs_count, 0x04, 0x03);
		debuglog("blobs_count_total: %d \n", blobs_count);
	} else {
		debuglog("Not found blob 04-03 in 6D --> 05-03 --> 04-04 --> 05-20\n");
	};

	return blobs_count;
};


//
// 04-03 msg buf processing
//
//
// 04-03 signed block
//
int get_04_03_blob_one(u8 *buf, int len, u8 *membuf, int *membuf_len, int index) {
	int ret;

	ret = main_unpack_getbuf_one(buf, len, membuf, membuf_len, index, 0x04, 0x03);
	if (ret == 1){
		if (membuf_len<=0) {
			debuglog("unpack_getbuf size error\n");
			return -1;
		};
		debuglog("MEMBUF_LEN: %d bytes\n", *membuf_len);
		show_memory(membuf, *membuf_len, "MEMBUF");
	} else {
		debuglog("04-03 blob not found\n");
		return -1;
	};

	return 1;
};


