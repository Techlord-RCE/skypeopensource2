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
// sess1pkt unkheader 6D cmd10
//
int encode41_sess1pkt_cmd10_recurs2(char *buf, int buf_limit_len){
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
    //blob.obj_data = 0xFFFFFFFF;
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


int encode41_sess1pkt_cmd10_recurs(char *buf, int buf_limit_len){
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
	intbuf_len=encode41_sess1pkt_cmd10_recurs2(intbuf,sizeof(intbuf));
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


int encode41_sess1pkt_cmd10(char *buf, int buf_limit_len){
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
	intbuf_len=encode41_sess1pkt_cmd10_recurs(intbuf,sizeof(intbuf));
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

20:32:12.518 T#1348 Logger AES dump from 00914C97 len 3A
20:32:12.518 T#1348 Before: 
20:32:12.518 T#1348 00 A6 01 41 05 04 EF DF 03 01 C9 00 00 02 00 01 
20:32:12.518 T#1348 6D 00 02 95 0F 05 03 41 03 00 01 F9 CA D5 F9 0B 
20:32:12.518 T#1348 00 03 07 04 04 12 41 04 00 01 10 00 0A FF FF FF 
20:32:12.518 T#1348 FF 0F 00 13 10 00 22 01 42 45 
===
PARAM send0034
===
{
04-EFEF: 1 bytes
0000: C9                                              | .                |

00-00: 02 00 00 00
00-01: 6D 00 00 00
00-02: 95 07 00 00
05-03: {
00-01: 79 65 35 BF
00-03: 07 00 00 00
04-04: 18 bytes
0000: 41 04 00 01 10 00 0A FF FF FF FF 0F 00 13 10 00 | A............... |
0010: 22 01                                           | ".               |

}
}
===

===
{
00-01: 10 00 00 00
00-0A: FF FF FF FF
00-13: 10 00 00 00
00-22: 01 00 00 00
}
===

--------------
and 
--------------

20:32:12.924 T#1348 Logger AES dump from 00914C97 len 3D
20:32:12.924 T#1348 Before: 
20:32:12.924 T#1348 00 A6 01 41 05 04 EF DF 03 03 E5 6E 60 00 00 02 
20:32:12.924 T#1348 00 01 6D 00 02 B4 FB 03 05 03 41 03 00 01 F9 CA 
20:32:12.924 T#1348 D5 F9 0B 00 03 0A 04 04 12 41 04 00 01 10 00 0A 
20:32:12.924 T#1348 D5 95 EB 83 01 00 13 10 00 22 01 D6 7E 
===
PARAM send0050
===
{
04-EFEF: 3 bytes
0000: E5 6E 60                                        | .n`              |

00-00: 02 00 00 00
00-01: 6D 00 00 00
00-02: B4 FD 00 00
05-03: {
00-01: 79 65 35 BF
00-03: 0A 00 00 00
04-04: 18 bytes
0000: 41 04 00 01 10 00 0A D5 95 EB 83 01 00 13 10 00 | A............... |
0010: 22 01                                           | ".               |

}
}
===

===
{
00-01: 10 00 00 00
00-0A: D5 CA 7A 10
00-13: 10 00 00 00
00-22: 01 00 00 00
}
===


*/
