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


extern u8 CREDENTIALS188[0x189];
extern uint CREDENTIALS188_LEN;

extern uint BLOB_0_1;


//
// sess1pkt 58 pkt
//
int encode41_sess1pkt_58_recurs(char *buf, int buf_limit_len){
	struct blob_s blob;
	int buf_len;
	int blobs_count;

	char intbuf[0x1000];
	int intbuf_len;

    memset(buf,0,sizeof(buf));
    buf_len=0;

	blobs_count = 0;

    buf_len=make_41cmdencode_recurs(buf, buf_len, blobs_count, 0);

	if ( buf_len > buf_limit_len ){
		debuglog("buffer limit overrun\n");
		return -1;
	};

	return buf_len;
};


int encode41_sess1pkt_58(char *buf, int buf_limit_len) {
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
    blob.obj_data = 0x58;
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

	// blob4 ALLOC1 recursive 41
	intbuf_len=encode41_sess1pkt_58_recurs(intbuf,sizeof(intbuf));
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

sess1pkt_58

20:32:12.112 T#1348 Logger AES dump from 00914C97 len 1D
20:32:12.112 T#1348 Before: 
20:32:12.112 T#1348 00 A6 01 41 05 04 EF DF 03 02 B9 80 00 00 02 00 
20:32:12.112 T#1348 01 58 00 02 A9 C3 01 05 03 41 00 06 82 
===
PARAM send0011
===
{
04-EFEF: 2 bytes
0000: B9 80                                           | ..               |

00-00: 02 00 00 00
00-01: 58 00 00 00
00-02: A9 61 00 00
05-03: <empty>
}
===

*/

