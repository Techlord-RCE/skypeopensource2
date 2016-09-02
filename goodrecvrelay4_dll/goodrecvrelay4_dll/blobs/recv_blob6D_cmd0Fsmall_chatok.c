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
extern int get_chatsync_stage();
extern unsigned int get_chatsync_streamid();
extern unsigned int get_remote_chatsync_streamid();


//
// cmd 0F (chat string ok pkt)
//
int encode41_sess1pkt_cmd0Fsmall_recurs2(char *buf, int buf_limit_len){
	struct blob_s blob;
	int buf_len;
	int blob_count;

	memset(buf,0,sizeof(buf));
    buf_len=0;

	blob_count = 3;

    buf_len=make_41cmdencode_recurs(buf, buf_len, blob_count, 0);

    // cmd -- blob1
    blob.obj_type = 0;
	blob.obj_index = 1;
    blob.obj_data = 0x0F;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // some flag -- blob2
    blob.obj_type = 0;
	blob.obj_index = 0x1C;
    blob.obj_data = 1;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // some flag -- blob3
    blob.obj_type = 0;
	blob.obj_index = 0x1D;
    blob.obj_data = 1;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	if ( buf_len > buf_limit_len ){
		debuglog("buffer limit overrun\n");
		return -1;
	};

	return buf_len;
};


int encode41_sess1pkt_cmd0Fsmall_recurs(char *buf, int buf_limit_len){
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

    // 00-03 stage -- blob2
    blob.obj_type = 0;
	blob.obj_index = 3;
	blob.obj_data = get_chatsync_stage();
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // ALLOC1 recursive 41 -- blob3
	intbuf_len=encode41_sess1pkt_cmd0Fsmall_recurs2(intbuf,sizeof(intbuf));
    blob.obj_type = 0x04;
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


int encode41_sess1pkt_cmd0Fsmall_chatok(char *buf, int buf_limit_len){
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

	// ALLOC1 recursive 41 -- blob4
	intbuf_len=encode41_sess1pkt_cmd0Fsmall_recurs(intbuf,sizeof(intbuf));
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

// chat string ok pkt

// http://wiki.epycslib.ru/index.php/Newdump5_three_msg_from_scratch
// PARAM recv0016

20:32:12.284 T#1348 Logger AES dump from 00915C16 len 2E
20:32:12.284 T#1348 Before: 
20:32:12.284 T#1348 DB DF 2B 7B 94 DB E8 D3 14 D9 19 81 C5 AB ED 05 
20:32:12.284 T#1348 B1 51 D5 42 AB B0 54 F2 22 FB 0F 16 AF 70 BA 4A 
20:32:12.284 T#1348 04 D3 10 4D 73 AD A5 8E B9 B1 98 4E F1 8F 
20:32:12.284 T#1348 After: 
20:32:12.284 T#1348 00 A6 01 41 04 00 00 02 00 01 6D 00 02 8D BF 03 
20:32:12.284 T#1348 05 03 41 03 00 01 BA D6 BF B2 0B 00 03 01 04 04 
20:32:12.284 T#1348 0B 41 03 00 01 0F 00 1C 01 00 1D 01 DB 44 
===
PARAM recv0016
===
{
00-00: 02 00 00 00
00-01: 6D 00 00 00
00-02: 8D DF 00 00
05-03: {
00-01: 3A EB 4F B6
00-03: 01 00 00 00
04-04: 11 bytes
0000: 41 03 00 01 0F 00 1C 01 00 1D 01                | A..........      |

}
}
===

===
{
00-01: 0F 00 00 00
00-1C: 01 00 00 00
00-1D: 01 00 00 00
}
===

*/
