//
// parse returned data
//

#include <stdio.h>
#include <stdlib.h>

#include "short_types.h"

#include "relays_util.h"

//#include "decode41.h"
#include "skype/skype_rc4.h"


extern struct _relays relays;

//
// 00-0F (for retrieve from cmd13)
//
int get_00_0F_blob(u8 *buf, int buf_len){
	int ret;
	unsigned long data_int;

    data_int = 0;
	debuglog("Looking for 00-0F (remote cmd) blob...\n");
	ret = main_unpack_checkblob(buf, buf_len, 0x00, 0x0F);
	if (ret == 1){
		debuglog("BLOB found!\n");
		main_unpack_getobj00(buf, buf_len, &data_int, 0x00, 0x0F);
		debuglog("00-0F (cmd13): 0x%08X\n", data_int);
	} else {
		debuglog("not found blob 00-0F in 6D --> 05-03 --> 04-04\n");
	};

	return data_int;
};


// get 05-2F 00-02: blob
int get_00_02_blob_new(char *membuf, int membuf_len){
	int data_int;
	int ret;

	data_int = 0;
	debuglog("Looking for 00-02 blob...\n");
	ret = main_unpack_checkblob(membuf, membuf_len, 0x00, 0x02);
	if (ret == 1){
		debuglog("BLOB found!\n");
		main_unpack_getobj00(membuf, membuf_len, &data_int, 0x00, 0x02);
		debuglog("00-02: 0x%08X\n", data_int);
	} else {
		debuglog("not found blob 00-02 in 6D --> 05-03 --> 04-04 --> 05-2F\n");
		//return 1;
	};

	return data_int;
};


//
// get_headers_chain_blobs_seq -- main function to get chains of blobs
//
int get_headers_chain_blobs_seq(char *membuf, int membuf_len){
	int data_int;
	int ret;
    int index;


    debuglog("00-09 blobs:\n");

    // for 00-09 (remote_headers_id)
	data_int = 0;
    index = 0;
    do { 
        debuglog("index = %d\n", index);
        ret = main_unpack_getobj00_seq(membuf, membuf_len, &data_int, index, 0x00, 0x09);
        if (ret) {
            debuglog("data_int = %08X\n", _bswap32(data_int));
            //debuglog("ret = %d\n", ret);
            add_header_chain(data_int, 0x00, 0x00, index);
            index++;
        };
    } while (ret);


    debuglog("00-0A blobs:\n");

    // for 00-0A (local_headers_id)
	data_int = 0;
    index = 0;
    do { 
        debuglog("index = %d\n", index);
        ret = main_unpack_getobj00_seq(membuf, membuf_len, &data_int, index, 0x00, 0x0A);
        if (ret) {
            debuglog("data_int = %08X\n", _bswap32(data_int));
            //debuglog("ret = %d\n", ret);
            add_header_chain(0x00, data_int, 0x00, index);
            index++;
        };
    } while (ret);


    debuglog("00-15 blobs:\n");

    // for 00-15 (header_id_crc)
	data_int = 0;
    index = 0;
    do { 
        debuglog("index = %d\n", index);
        ret = main_unpack_getobj00_seq(membuf, membuf_len, &data_int, index, 0x00, 0x15);
        if (ret) {
            debuglog("data_int = %08X\n", _bswap32(data_int));
            //debuglog("ret = %d\n", ret);
            add_header_chain(0x00, 0x00, data_int, index);
            index++;
        };
    } while (ret);


	return 0;
};


//
// only for init session cmd13 -- find chain1
//
int get_headers_chain_blobs_seq2_cmd13recv_getchainbyindex(char *membuf, int membuf_len,
                    int index1, int index2, int index3,
                    uint *remote_header, uint *header_id_crc, uint *local_header) {
	int data_int;
	int ret;
    int index;

    // for cmd13recv local and remote headers swaped
    // 00-09 -- our local headers
    // 00-0A -- the remote headers (for us)
/*
00-09: C7 88 8F 54
00-0A: A5 49 25 0C
00-15: F0 36 B4 BB
*/


    //debuglog("00-09 blobs:\n");

    // for 00-09 (local_headers_id)
    index = index1;
    if (1) {
    	data_int = 0;
        //debuglog("index = %d\n", index);
        ret = main_unpack_getobj00_seq(membuf, membuf_len, &data_int, index, 0x00, 0x09);
        if (ret) {
            //debuglog("data_int = %08X\n", _bswap32(data_int));
            *local_header = data_int;
        };
    };

    //debuglog("00-0A blobs:\n");

    // for 00-0A (remote_headers_id)
    index = index2;
    if (1) { 
    	data_int = 0;
        //debuglog("index = %d\n", index);
        ret = main_unpack_getobj00_seq(membuf, membuf_len, &data_int, index, 0x00, 0x0A);
        if (ret) {
            //debuglog("data_int = %08X\n", _bswap32(data_int));
            *remote_header = data_int;
        };
    };

    //debuglog("00-15 blobs:\n");

    // for 00-15 (header_id_crc)
    index = index3;
    if (1) { 
    	data_int = 0;
        //debuglog("index = %d\n", index);
        ret = main_unpack_getobj00_seq(membuf, membuf_len, &data_int, index, 0x00, 0x15);
        if (ret) {
            //debuglog("data_int = %08X\n", _bswap32(data_int));
            *header_id_crc = data_int;
        };
    };

	return 0;
};


//
// 00-25 (get cmd10recv need_sync flag) 
//
int get_00_25_blob(u8 *buf, int buf_len){
    int ret;
    unsigned long data_int;

    data_int = 0;
    debuglog("Looking for 00-25 blob...\n");
    ret = main_unpack_checkblob(buf, buf_len, 0x00, 0x25);
    if (ret == 1){
        debuglog("BLOB found!\n");
        main_unpack_getobj00(buf, buf_len, &data_int, 0x00, 0x25);
        debuglog("00-25 (need_sync flag): 0x%08X\n", data_int);
    } else {
        debuglog("not found blob 00-25 in cmd10recv pkt\n");
    };

    return data_int;
};
