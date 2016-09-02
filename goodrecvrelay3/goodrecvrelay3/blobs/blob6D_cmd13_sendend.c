//
// session 1 pkt
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../decode41.h"

extern int show_memory(char *mem, int len, char *text);
extern int set_packet_size(char *a1, int c);
extern int encode_to_7bit(char *buf, uint word, uint limit);

extern int make_41cmdencodeA6(char *buf, int buf_len, uint blob_count, uint session_id, uint session_cmd, int dodebug);

extern int make_41cmdencode_recurs(char *buf, int buf_len, uint blob_count, int dodebug);
extern int make_41cmdencode(char *buf, int buf_len, uint blob_count, uint session_id, uint session_cmd, int dodebug);
extern int make_41encode(char *buf, int buf_len, char *blobptr, int dodebug);

extern int get_cmdid_seqnum();


extern u8 MSG_TEXT[0x100];
extern u8 CHAT_STRING[0x100];
extern u8 CHAT_PEERS[0x100];
extern u8 CREDENTIALS[0x105];
extern uint CREDENTIALS_LEN;
extern u8 NEWBLK[0x1000];
extern uint NEWBLK_LEN;
extern u8 REMOTE_NAME[0x100];

extern uint START_HEADER_ID;


//
// session cmd13end (send0033 sendend pkt)
//
int encode41_cmd13end_recurs3(char *buf, int buf_limit_len){
	struct blob_s blob;
	int buf_len;
	int blob_count;
	u8 str_null[]="";

	memset(buf,0,sizeof(buf));
    buf_len=0;

	blob_count = 2;

    buf_len=make_41cmdencode_recurs(buf, buf_len, blob_count, 0);

    // null string -- blob1
    blob.obj_type = 3;
	blob.obj_index = 0x00;
    blob.obj_data = 0;
	blob.data_ptr = (int)str_null;
	blob.data_size = strlen(str_null)+1;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // null string -- blob1
    blob.obj_type = 3;
	blob.obj_index = 0x01;
    blob.obj_data = 0;
	blob.data_ptr = (int)str_null;
	blob.data_size = strlen(str_null)+1;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	if ( buf_len > buf_limit_len ){
		debuglog("buffer limit overrun\n");
		return -1;
	};

	return buf_len;
};


int encode41_cmd13end_recurs2(char *buf, int buf_limit_len){
	struct blob_s blob;
	int buf_len;
	int blob_count;

	char intbuf[0x1000];
	int intbuf_len;

	memset(buf,0,sizeof(buf));
    buf_len=0;

	blob_count = 3;

    buf_len=make_41cmdencode_recurs(buf, buf_len, blob_count, 0);

    // sync chat cmd -- blob1
    blob.obj_type = 0;
	blob.obj_index = 1;
    blob.obj_data = 0x13;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // header_id remote last -- blob2
    blob.obj_type = 0;
	blob.obj_index = 0x0F;
    blob.obj_data = START_HEADER_ID + 1;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	// ALLOC2 recursive -- blob3
	intbuf_len=encode41_cmd13end_recurs3(intbuf,sizeof(intbuf));
    blob.obj_type = 5;
	blob.obj_index = 0x2F;
    blob.obj_data = 0;
	blob.data_ptr = (int)intbuf;
	blob.data_size = intbuf_len;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	if ( buf_len > buf_limit_len ){
		debuglog("buffer limit overrun\n");
		return -1;
	};

	return buf_len;
};


int encode41_cmd13end_recurs(char *buf, int buf_limit_len){
	struct blob_s blob;
	uint session_id;
	uint session_cmd;
	int buf_len;
	int blob_count;

	char intbuf[0x1000];
	int intbuf_len;

	session_id=00;
	session_cmd=0xA6;

	memset(buf,0,sizeof(buf));
    buf_len=0;

	blob_count = 3;

    buf_len=make_41cmdencode_recurs(buf, buf_len, blob_count, 0);

    // our chat seq id -- blob1
    blob.obj_type = 0;
	blob.obj_index = 1;
	blob.obj_data = get_chatsync_streamid();
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // stage -- blob2
    blob.obj_type = 0;
	blob.obj_index = 3;
	blob.obj_data = get_chatsync_stage();
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // blob3 -- ALLOC1 recursive 41
	intbuf_len=encode41_cmd13end_recurs2(intbuf,sizeof(intbuf));
    blob.obj_type = 4;
	blob.obj_index = 0x04;
    blob.obj_data = 0;
	blob.data_ptr = (int)intbuf;
	blob.data_size = intbuf_len;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	if ( buf_len > buf_limit_len ){
		debuglog("buffer limit overrun\n");
		return -1;
	};

	return buf_len;
};


int encode41_sess1pkt_cmd13end(char *buf, int buf_limit_len){
	struct blob_s blob;
	uint session_id;
	uint session_cmd;
	int buf_len;
	int blob_count;

	char intbuf[0x1000];
	int intbuf_len;

	session_id=00;
	session_cmd=0xA6;

	memset(buf,0,sizeof(buf));
    buf_len=0;

	blob_count = 4;

    buf_len=make_41cmdencodeA6(buf, buf_len, blob_count, session_id, session_cmd, 0);

    // cmd type -- blob1
    blob.obj_type = 0;
	blob.obj_index = 0;
    blob.obj_data = 0x02;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // cmd -- blob2
    blob.obj_type = 0;
	blob.obj_index = 1;
    blob.obj_data = 0x6D;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // cmd uniq id -- blob3
    blob.obj_type = 0;
	blob.obj_index = 2;
	blob.obj_data = get_cmdid_seqnum();
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	// blob4 -- ALLOC1 recursive
	intbuf_len=encode41_cmd13end_recurs(intbuf,sizeof(intbuf));
    blob.obj_type = 5;
	blob.obj_index = 3;
    blob.obj_data = 0;
	blob.data_ptr = (int)intbuf;
	blob.data_size = intbuf_len;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	if ( buf_len > buf_limit_len ){
		debuglog("buffer limit overrun\n");
		return -1;
	};

	return buf_len;
};


/*

sess1pkt cmd13end

20:32:12.518 T#1348 Logger AES dump from 00914C97 len 41
20:32:12.518 T#1348 Before: 
20:32:12.518 T#1348 00 A6 01 41 05 04 EF DF 03 03 79 C7 19 00 00 02 
20:32:12.518 T#1348 00 01 6D 00 02 EC C8 03 05 03 41 03 00 01 F9 CA 
20:32:12.518 T#1348 D5 F9 0B 00 03 06 04 04 16 41 03 00 01 13 00 0F 
20:32:12.518 T#1348 AA D7 D4 B1 01 05 2F 41 02 03 00 00 03 01 00 3C 
20:32:12.518 T#1348 B5 
===
PARAM send0033
===
{
04-EFEF: 3 bytes
0000: 79 C7 19                                        | y..              |

00-00: 02 00 00 00
00-01: 6D 00 00 00
00-02: 6C E4 00 00
05-03: {
00-01: 79 65 35 BF
00-03: 06 00 00 00
04-04: 22 bytes
0000: 41 03 00 01 13 00 0F AA D7 D4 B1 01 05 2F 41 02 | A............/A. |
0010: 03 00 00 03 01 00                               | ......           |

}
}
===

===
{
00-01: 13 00 00 00
00-0F: AA 2B 35 16
05-2F: {
03-00: ""
03-01: ""
}
}
===

*/
