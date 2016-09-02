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
// cmd23 (new chat init request)
//
int encode41_sess1pkt_cmd23_recurs2(char *buf, int buf_limit_len){
	struct blob_s blob;
	int buf_len;
	int blob_count;

	memset(buf,0,sizeof(buf));
    buf_len=0;

	blob_count = 1;

    buf_len=make_41cmdencode_recurs(buf, buf_len, blob_count, 0);

    // cmd -- blob1
    blob.obj_type = 0;
	blob.obj_index = 1;
    blob.obj_data = 0x23;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	if ( buf_len > buf_limit_len ){
		debuglog("buffer limit overrun\n");
		return -1;
	};

	return buf_len;
};


int encode41_sess1pkt_cmd23_recurs(char *buf, int buf_limit_len){
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

	blob_count = 5;

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
	intbuf_len=encode41_sess1pkt_cmd23_recurs2(intbuf,sizeof(intbuf));
    blob.obj_type = 0x04;
	blob.obj_index = 0x04;
    blob.obj_data = 0;
	blob.data_ptr = (int)intbuf;
	blob.data_size = intbuf_len;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // some flag -- blob4
    blob.obj_type = 0;
	blob.obj_index = 7;
	blob.obj_data = 0x0A;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // remote chat seq id -- blob5
    blob.obj_type = 0;
	blob.obj_index = 2;
	blob.obj_data = get_remote_chatsync_streamid();
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	if ( buf_len > buf_limit_len ){
		debuglog("buffer limit overrun\n");
		return -1;
	};

	return buf_len;
};


int encode41_sess1pkt_cmd23_initreq(char *buf, int buf_limit_len){
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
	intbuf_len=encode41_sess1pkt_cmd23_recurs(intbuf,sizeof(intbuf));
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

// new chat init req

// http://wiki.epycslib.ru/index.php/Newdump5_three_msg_from_scratch
// PARAM recv0009

20:32:12.127 T#1348 Logger AES dump from 00915C16 len 39
20:32:12.127 T#1348 Before: 
20:32:12.127 T#1348 EC AC AF F7 C0 B3 FE DD 17 B8 30 0A 67 57 52 07 
20:32:12.127 T#1348 30 95 11 8B 6C 07 6F 28 28 DA 80 D6 40 2D 11 BA 
20:32:12.127 T#1348 13 E1 DA BA 7F CB 51 55 F0 C5 7B 7E 53 2C BC A2 
20:32:12.127 T#1348 77 76 E3 D3 3F 9C 8C C6 93 
20:32:12.127 T#1348 After: 
20:32:12.127 T#1348 00 A6 01 41 05 04 EF DF 03 02 56 B8 00 00 02 00 
20:32:12.127 T#1348 01 6D 00 02 92 EC 01 05 03 41 05 00 01 BA D6 BF 
20:32:12.127 T#1348 B2 0B 00 03 00 04 04 05 41 01 00 01 23 00 07 0A 
20:32:12.127 T#1348 00 02 F9 CA D5 F9 0B 72 BE 
===
PARAM recv0009
===
{
04-EFEF: 2 bytes
0000: 56 B8                                           | V.               |

00-00: 02 00 00 00
00-01: 6D 00 00 00
00-02: 12 76 00 00
05-03: {
00-01: 3A EB 4F B6
00-03: 00 00 00 00
04-04: 5 bytes
0000: 41 01 00 01 23                                  | A...#            |

00-07: 0A 00 00 00
00-02: 79 65 35 BF
}
}
===

===
{
00-01: 23 00 00 00
}
===

*/
