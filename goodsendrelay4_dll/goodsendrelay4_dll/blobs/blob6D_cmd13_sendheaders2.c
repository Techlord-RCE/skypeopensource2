//
// session 7 pkt
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

extern u8 MSG_TEXT[0x100];
extern u8 CHAT_STRING[0x100];
extern u8 CHAT_PEERS[0x100];
extern u8 CREDENTIALS[0x105];
extern uint CREDENTIALS_LEN;
extern u8 NEWBLK[0x1000];
extern uint NEWBLK_LEN;
extern u8 REMOTE_NAME[0x100];

extern u8 CHAT_PEERS_REVERSED[0x100];
extern uint HEADER_ID_REMOTE_LAST;
extern uint HEADER_ID_SEND;

extern uint START_HEADER_ID;
extern uint pkt_cmd13_BLOB_00_0F;

extern uint HEADER_SLOT_CRC1;
extern uint HEADER_SLOT_CRC2;
extern uint HEADER_SLOT_CRC3;

extern uint BLOB_0_1;
extern uint BLOB_0_7;
extern uint BLOB_0_9;
extern uint BLOB_0_2__1;


//
// sess1pkt_cmd13 (send0024)
//
int encode41_sess1pkt_cmd13_recurs5(char *buf, int buf_limit_len){
	struct blob_s blob;
	int buf_len;
	int blob_count;

	memset(buf,0,sizeof(buf));
    buf_len=0;

	blob_count = 1;

    buf_len=make_41cmdencode_recurs(buf, buf_len, blob_count, 0);

    // number of headers (05-14) in this packet -- blob1
    blob.obj_type = 0;
	blob.obj_index = 2;
    blob.obj_data = 2;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	if ( buf_len > buf_limit_len ){
		debuglog("buffer limit overrun\n");
		return -1;
	};

	return buf_len;
};


int encode41_sess1pkt_cmd13_recurs4(char *buf, int buf_limit_len){
	struct blob_s blob;
	int buf_len;
	int blob_count;

	memset(buf,0,sizeof(buf));
    buf_len=0;

	blob_count = 3;

    buf_len=make_41cmdencode_recurs(buf, buf_len, blob_count, 0);

    // (start_header_id + 1) -- blob1
    blob.obj_type = 0;
	blob.obj_index = 0x09;
	blob.obj_data = pkt_cmd13_BLOB_00_0F + 1;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // (start_header_id + 1) (the same) -- blob2
    blob.obj_type = 0;
	blob.obj_index = 0x0A;
	blob.obj_data = pkt_cmd13_BLOB_00_0F + 1;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // some unknown (maybe headers block crc) -- blob3
    blob.obj_type = 0;
	blob.obj_index = 0x15;
	blob.obj_data = HEADER_SLOT_CRC2;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	if ( buf_len > buf_limit_len ){
		debuglog("buffer limit overrun\n");
		return -1;
	};

	return buf_len;
};



int encode41_sess1pkt_cmd13_recurs3(char *buf, int buf_limit_len){
	struct blob_s blob;
	int buf_len;
	int blob_count;

	memset(buf,0,sizeof(buf));
    buf_len=0;

	blob_count = 4;

    buf_len=make_41cmdencode_recurs(buf, buf_len, blob_count, 0);

    // start_header_id -- blob1
    blob.obj_type = 0;
	blob.obj_index = 0x09;
	blob.obj_data = pkt_cmd13_BLOB_00_0F;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // start_header_id (the same) -- blob2
    blob.obj_type = 0;
	blob.obj_index = 0x0A;
	blob.obj_data = pkt_cmd13_BLOB_00_0F;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // some unknown (maybe headers block crc) -- blob3
    blob.obj_type = 0;
	blob.obj_index = 0x15;
	blob.obj_data = HEADER_SLOT_CRC1;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // some flag -- blob4
    blob.obj_type = 0;
	blob.obj_index = 0x2E;
    blob.obj_data = 0x04;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	if ( buf_len > buf_limit_len ){
		debuglog("buffer limit overrun\n");
		return -1;
	};

	return buf_len;
};


//
// main include blobs recursion
// 
int encode41_sess1pkt_cmd13_recurs2(char *buf, int buf_limit_len){
	struct blob_s blob;
	int buf_len;
	int blob_count;

	char intbuf[0x1000];
	int intbuf_len;

	char intbuf2[0x1000];
	int intbuf2_len;

	memset(buf,0,sizeof(buf));
    buf_len=0;

	blob_count = 6;

    buf_len=make_41cmdencode_recurs(buf, buf_len, blob_count, 0);

    // cmdid, send headers -- blob1
    blob.obj_type = 0;
	blob.obj_index = 1;
    blob.obj_data = 0x13;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // header_id remote last -- blob2
    blob.obj_type = 0;
	blob.obj_index = 0x0F;
	blob.obj_data = pkt_cmd13_BLOB_00_0F;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // ALLOC1 recursive -- blob3
	intbuf_len=encode41_sess1pkt_cmd13_recurs3(intbuf,sizeof(intbuf));
    blob.obj_type = 5;
	blob.obj_index = 0x14;
    blob.obj_data = 0;
	blob.data_ptr = (int)intbuf;
	blob.data_size = intbuf_len;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // ALLOC2 recursive -- blob4
	intbuf_len=encode41_sess1pkt_cmd13_recurs4(intbuf,sizeof(intbuf));
    blob.obj_type = 5;
	blob.obj_index = 0x14;
    blob.obj_data = 0;
	blob.data_ptr = (int)intbuf;
	blob.data_size = intbuf_len;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // chat peers -- blob5
    blob.obj_type = 3;
	blob.obj_index = 0x12;
    blob.obj_data = 0;
//	blob.data_ptr = (int)CHAT_PEERS_REVERSED
//	blob.data_size = strlen(CHAT_PEERS_REVERSED)+1;
	blob.data_ptr = (int)CHAT_PEERS;
	blob.data_size = strlen(CHAT_PEERS)+1;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	// number of headers chains in this packet -- blob6
	intbuf2_len=encode41_sess1pkt_cmd13_recurs5(intbuf2,sizeof(intbuf2));
    blob.obj_type = 5;
	blob.obj_index = 0x2F;
    blob.obj_data = 0;
	blob.data_ptr = (int)intbuf2;
	blob.data_size = intbuf2_len;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	if ( buf_len > buf_limit_len ){
		debuglog("buffer limit overrun\n");
		return -1;
	};

	return buf_len;
};


int encode41_sess1pkt_cmd13_recurs(char *buf, int buf_limit_len){
	struct blob_s blob;
	int buf_len;
	int blob_count;

	char intbuf[0x1000];
	int intbuf_len;

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

    // blob3 ALLOC1 recursive 41
	intbuf_len=encode41_sess1pkt_cmd13_recurs2(intbuf,sizeof(intbuf));
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


int encode41_sess1pkt_cmd13(char *buf, int buf_limit_len){
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
	intbuf_len=encode41_sess1pkt_cmd13_recurs(intbuf,sizeof(intbuf));
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

sess1pkt_cmd13

===
PARAM send023
===
{
04-EFEF: 2 bytes
0000: D1 1F                                           | ..               |

00-00: 02 00 00 00
00-01: 6D 00 00 00
00-02: 54 8A 00 00
05-03: {
00-01: 1B 75 E1 D3
00-03: 03 00 00 00
04-04: 107 bytes
0000: 41 06 00 01 13 00 0F C7 91 BE A4 05 05 14 41 04 | A.............A. |
0010: 00 09 C7 91 BE A4 05 00 0A C7 91 BE A4 05 00 15 | ................ |
0020: C3 84 9C B2 0B 00 2E 04 05 14 41 03 00 09 C8 91 | ..........A..... |
0030: BE A4 05 00 0A C8 91 BE A4 05 00 15 A5 D6 D6 E3 | ................ |
0040: 02 03 12 6E 6F 74 6E 6F 77 61 67 61 69 6E 70 6C | ...notnowagainpl |
0050: 65 61 73 65 20 74 68 65 6D 61 67 69 63 66 6F 72 | ease themagicfor |
0060: 79 6F 75 00 05 2F 41 01 00 02 02                | you../A....      |

}
}
===
===
{
00-01: 13 00 00 00
00-0F: C7 88 8F 54
05-14: {
00-09: C7 88 8F 54
00-0A: C7 88 8F 54
00-15: 43 02 47 B6
00-2E: 04 00 00 00
}
05-14: {
00-09: C8 88 8F 54
00-0A: C8 88 8F 54
00-15: 25 AB 75 2C
}
03-12: "notnowagainplease themagicforyou"
05-2F: {
00-02: 02 00 00 00
}
}
===

*/
