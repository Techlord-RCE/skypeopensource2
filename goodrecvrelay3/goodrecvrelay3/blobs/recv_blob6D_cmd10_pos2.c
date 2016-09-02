//
// session unknown header pkt (gimme header id)
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

extern u8 CREDENTIALS188[0x189];
extern uint CREDENTIALS188_LEN;

extern uint BLOB_0_1;

extern uint HEADER_ID_REMOTE_LAST;
extern uint HEADER_ID_SEND;


//
// sess1pkt unkheader 6D cmd10 pos2
//
int encode41_sess1pkt_cmd10r_pos2_recurs2(char *buf, int buf_limit_len){
	struct blob_s blob;
	int buf_len;
	int blob_count;

	memset(buf,0,sizeof(buf));
    buf_len=0;

	blob_count = 4;

    buf_len=make_41cmdencode_recurs(buf, buf_len, blob_count, 0);

    // chat cmd -- blob1
    blob.obj_type = 0;
	blob.obj_index = 1;
    blob.obj_data = 0x10;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // unknown header id -- blob2 
    blob.obj_type = 0;
	blob.obj_index = 0x0A;
    blob.obj_data = HEADER_ID_SEND;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // some flag -- blob3
    blob.obj_type = 0;
	blob.obj_index = 0x13;
    blob.obj_data = 0x10;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // some flag2 -- blob4
    blob.obj_type = 0;
	blob.obj_index = 0x22;
    blob.obj_data = 0x01;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	if ( buf_len > buf_limit_len ){
		debuglog("buffer limit overrun\n");
		return -1;
	};

	return buf_len;
};


int encode41_sess1pkt_cmd10r_pos2_recurs(char *buf, int buf_limit_len){
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

    // blob3 ALLOC1 recursive 41
	intbuf_len=encode41_sess1pkt_cmd10r_pos2_recurs2(intbuf,sizeof(intbuf));
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


int encode41_sess1pkt_cmd10r_pos2(char *buf, int buf_limit_len){
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

	// blob4 -- ALLOC1 recursive 41
	intbuf_len=encode41_sess1pkt_cmd10r_pos2_recurs(intbuf,sizeof(intbuf));
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

sess1pkt

06:07:54.619 T#5096 Logger AES dump from 00915C16 len 40
06:07:54.619 T#5096 Before: 
06:07:54.619 T#5096 EF 7A 28 CB 26 47 A3 1E D5 FE 33 27 C2 AC B1 45 
06:07:54.619 T#5096 69 6F FF 36 06 59 C8 45 E6 3E 1F 7C B9 61 F7 63 
06:07:54.619 T#5096 FC B9 CC 19 D4 A9 56 9E 5F D7 97 2F 6D 35 14 03 
06:07:54.619 T#5096 13 5C F6 E8 0A 37 21 07 D9 00 F4 6F 1D 20 20 CC 
06:07:54.619 T#5096 After: 
06:07:54.619 T#5096 00 A6 01 41 05 04 EF DF 03 03 33 3A 77 00 00 02 
06:07:54.619 T#5096 00 01 6D 00 02 F7 E6 01 05 03 41 03 00 01 9D FF 
06:07:54.619 T#5096 BF E4 06 00 03 03 04 04 15 41 05 00 01 10 00 0A 
06:07:54.619 T#5096 F5 CD 9A 82 01 00 13 10 00 22 01 00 25 01 7E CC 
06:07:54.619 T#5096 Logger AES dump from 00914C97 len 15
===
PARAM recv0016
===
{
04-EFEF: 3 bytes
0000: 33 3A 77                                        | 3:w              |

00-00: 02 00 00 00
00-01: 6D 00 00 00
00-02: 77 73 00 00
05-03: {
00-01: 9D FF 8F 6C
00-03: 03 00 00 00
04-04: 21 bytes
0000: 41 05 00 01 10 00 0A F5 CD 9A 82 01 00 13 10 00 | A............... |
0010: 22 01 00 25 01                                  | "..%.            |

}
}
===

===
{
00-01: 10 00 00 00
00-0A: F5 A6 46 10
00-13: 10 00 00 00
00-22: 01 00 00 00
}
===

*/
