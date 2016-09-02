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

extern uint HEADER_ID_LOCAL_FIRST;
extern uint HEADER_ID_LOCAL_LAST;

extern uint HEADER_ID_CMD13R4_ID;


int encode41_cmd13r4_recurs2(char *buf, int buf_limit_len){
	struct blob_s blob;
	int buf_len;
	int blob_count;

	char intbuf[0x1000];
	int intbuf_len;

	memset(buf,0,sizeof(buf));
    buf_len=0;

	blob_count = 3;

    buf_len=make_41cmdencode_recurs(buf, buf_len, blob_count, 0);

    // cmd -- blob1
    blob.obj_type = 0;
	blob.obj_index = 1;
    blob.obj_data = 0x13;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // local_headers_last -- blob2
    blob.obj_type = 0;
	blob.obj_index = 0x0F;
    //blob.obj_data = 0x27AAA1B3;
    //blob.obj_data = HEADER_ID_LOCAL_LAST;
    blob.obj_data = HEADER_ID_CMD13R4_ID;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // chat peers -- blob3
    blob.obj_type = 3;
	blob.obj_index = 0x12;
    blob.obj_data = 0;
	blob.data_ptr = (int)CHAT_PEERS;
	blob.data_size = strlen(CHAT_PEERS)+1;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	if ( buf_len > buf_limit_len ){
		debuglog("buffer limit overrun\n");
		return -1;
	};

	return buf_len;
};


int encode41_cmd13r4_recurs(char *buf, int buf_limit_len){
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
	intbuf_len=encode41_cmd13r4_recurs2(intbuf,sizeof(intbuf));
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


int encode41_sess1pkt_cmd13r4_sendheaders4(char *buf, int buf_limit_len){
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
	intbuf_len=encode41_cmd13r4_recurs(intbuf,sizeof(intbuf));
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

sess1pkt cmd13r4_sendheaders4

===
PARAM send013
===
{
04-EFEF: 2 bytes
0000: FC 56                                           | .V               |

00-00: 02 00 00 00
00-01: 6D 00 00 00
00-02: A3 86 00 00
05-03: {
00-01: D5 F2 DD A2
00-03: 01 00 00 00
04-04: 47 bytes
0000: 41 03 00 01 13 00 0F B3 C3 AA BD 02 03 12 6E 6F | A.............no |
0010: 74 6E 6F 77 61 67 61 69 6E 70 6C 65 61 73 65 20 | tnowagainplease  |
0020: 74 68 65 6D 61 67 69 63 66 6F 72 79 6F 75 00    | themagicforyou.  |

}
}
===
===
{
00-01: 13 00 00 00
00-0F: B3 A1 AA 27
03-12: "notnowagainplease themagicforyou"
}
===

*/
