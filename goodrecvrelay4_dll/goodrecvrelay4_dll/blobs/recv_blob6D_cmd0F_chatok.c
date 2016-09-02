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
int encode41_sess1pkt_cmd0F_recurs2(char *buf, int buf_limit_len){
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


int encode41_sess1pkt_cmd0F_recurs(char *buf, int buf_limit_len){
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
	intbuf_len=encode41_sess1pkt_cmd0F_recurs2(intbuf,sizeof(intbuf));
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


int encode41_sess1pkt_cmd0F_chatok(char *buf, int buf_limit_len){
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
	intbuf_len=encode41_sess1pkt_cmd0F_recurs(intbuf,sizeof(intbuf));
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

// http://wiki.epycslib.ru/index.php/Newdump3_one_msg
// PARAM recv0012

09:50:10.042 T#1544 Logger AES dump from 00915C16 len 3E
09:50:10.042 T#1544 Before: 
09:50:10.042 T#1544 FF C4 5A E1 B2 AC 2D 00 D1 97 F0 E0 19 C5 B4 72 
09:50:10.042 T#1544 3D 6C 20 7E 89 DB C4 2A 46 48 D0 32 89 C8 A8 21 
09:50:10.042 T#1544 0E FF F6 63 95 2C 4F 4B B7 10 60 81 B7 6A 88 A1 
09:50:10.042 T#1544 D6 B7 72 75 AC 04 60 FC AA 93 DB 43 7E F7 
09:50:10.042 T#1544 After: 
09:50:10.042 T#1544 00 A6 01 41 05 04 EF DF 03 01 E4 00 00 02 00 01 
09:50:10.042 T#1544 6D 00 02 C0 80 01 05 03 41 05 00 01 CC E0 9A 8A 
09:50:10.042 T#1544 0C 00 03 00 04 04 0B 41 03 00 01 0F 00 1C 01 00 
09:50:10.042 T#1544 1D 01 00 07 0A 00 02 C0 EE E2 8A 0B 59 EF 
===
PARAM recv0012
===
{
04-EFEF: 1 bytes
0000: E4                                              | .                |

00-00: 02 00 00 00
00-01: 6D 00 00 00
00-02: 40 40 00 00
05-03: {
00-01: 4C B0 46 C1
00-03: 00 00 00 00
04-04: 11 bytes
0000: 41 03 00 01 0F 00 1C 01 00 1D 01                | A..........      |

00-07: 0A 00 00 00
00-02: 40 B7 58 B1
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
