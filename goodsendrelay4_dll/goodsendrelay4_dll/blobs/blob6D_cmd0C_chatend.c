//
// session pkt
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


extern u8 CHAT_PEERS_REVERSED[0x100];
extern u8 CHAT_PEERS[0x100];

extern uint global_unknown_cmd24_signed_id;
extern uint global_unknown_cmd2A_signed_id;

extern uint global_msg_time_sec;
extern uint global_msg_time_min;


//
// sess1pkt chatend 6D_cmd0C
//
int encode41_sess1pkt_cmd0C_recurs2(char *buf, int buf_limit_len){
	struct blob_s blob;
	int buf_len;
	int blob_count;

	char intbuf[0x1000];
	int intbuf_len;

	memset(buf,0,sizeof(buf));
    buf_len=0;

	blob_count = 5;

    buf_len=make_41cmdencode_recurs(buf, buf_len, blob_count, 0);

    // chat cmd -- blob1
    blob.obj_type = 0;
	blob.obj_index = 1;
    blob.obj_data = 0x0C;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // chat peers reversed -- blob2
    blob.obj_type = 3;
	blob.obj_index = 0x12;
    blob.obj_data = 0;
	//blob.data_ptr = (int)CHAT_PEERS_REVERSED;
	//blob.data_size = strlen(CHAT_PEERS_REVERSED)+1;
	blob.data_ptr = (int)CHAT_PEERS;
	blob.data_size = strlen(CHAT_PEERS)+1;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // recursive 41 -- blob3
    memcpy(intbuf,"\x00\x01",2);
	intbuf_len=2;
    blob.obj_type = 4;
	blob.obj_index = 0x24;
    blob.obj_data = 0;
	blob.data_ptr = (int)intbuf;
	blob.data_size = intbuf_len;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // some indexes -- blob4
    blob.obj_type = 6;
	blob.obj_index = 0x34;
    blob.obj_data = 2;
	//blob.data_ptr = global_unknown_cmd24_signed_id;
	//blob.data_size = global_unknown_cmd2A_signed_id;
	blob.data_ptr = global_unknown_cmd2A_signed_id;
	blob.data_size = global_unknown_cmd24_signed_id;
    buf_len=make_41encode_type6(buf,buf_len,(char *)&blob, 0);

    // hz -- blob5
    blob.obj_type = 6;
	blob.obj_index = 0x4D;
    blob.obj_data = 2;
	//blob.data_ptr = time(NULL) / 60;
	//blob.data_size = time(NULL) / 60;
	blob.data_ptr = global_msg_time_min;
	blob.data_size = global_msg_time_min;
    buf_len=make_41encode_type6(buf,buf_len,(char *)&blob, 0);

	if ( buf_len > buf_limit_len ){
		debuglog("buffer limit overrun\n");
		return -1;
	};

	return buf_len;
};


int encode41_sess1pkt_cmd0C_recurs(char *buf, int buf_limit_len){
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
	intbuf_len=encode41_sess1pkt_cmd0C_recurs2(intbuf,sizeof(intbuf));
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


int encode41_sess1pkt_cmd0C(char *buf, int buf_limit_len){
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
	intbuf_len=encode41_sess1pkt_cmd0C_recurs(intbuf,sizeof(intbuf));
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

20:32:12.518 T#1348 Logger AES dump from 00914C97 len 70
20:32:12.518 T#1348 Before: 
20:32:12.518 T#1348 00 A6 01 41 05 04 EF DF 03 03 12 E2 C3 00 00 02 
20:32:12.518 T#1348 00 01 6D 00 02 C3 82 03 05 03 41 03 00 01 F9 CA 
20:32:12.518 T#1348 D5 F9 0B 00 03 05 04 04 45 41 05 00 01 0C 03 12 
20:32:12.518 T#1348 6E 6F 74 6E 6F 77 61 67 61 69 6E 70 6C 65 61 73 
20:32:12.518 T#1348 65 20 74 68 65 6D 61 67 69 63 66 6F 72 79 6F 75 
20:32:12.518 T#1348 00 04 24 02 01 00 06 34 02 C5 B1 D6 8E 02 A2 92 
20:32:12.518 T#1348 BA A0 04 06 4D 02 8F FE 94 0B 8F FE 94 0B EE 2F 
===
PARAM send0032
===
{
04-EFEF: 3 bytes
0000: 12 E2 C3                                        | ...              |

00-00: 02 00 00 00
00-01: 6D 00 00 00
00-02: 43 C1 00 00
05-03: {
00-01: 79 65 35 BF
00-03: 05 00 00 00
04-04: 69 bytes
0000: 41 05 00 01 0C 03 12 6E 6F 74 6E 6F 77 61 67 61 | A......notnowaga |
0010: 69 6E 70 6C 65 61 73 65 20 74 68 65 6D 61 67 69 | inplease themagi |
0020: 63 66 6F 72 79 6F 75 00 04 24 02 01 00 06 34 02 | cforyou..$....4. |
0030: C5 B1 D6 8E 02 A2 92 BA A0 04 06 4D 02 8F FE 94 | ...........M.... |
0040: 0B 8F FE 94 0B                                  | .....            |

}
}
===

===
{
00-01: 0C 00 00 00
03-12: "notnowagainplease themagicforyou"
04-24: 2 bytes
0000: 01 00                                           | ..               |

06-34: C5 98 D5 21, 22 89 0E 44
06-4D: 0F 3F 65 01, 0F 3F 65 01
}
===

*/

