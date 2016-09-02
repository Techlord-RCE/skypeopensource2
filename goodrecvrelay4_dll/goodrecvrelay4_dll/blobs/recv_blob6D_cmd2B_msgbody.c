//
// session 3 pkt
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

extern uint BLOB_0_1;
extern uint BLOB_0_2__1;

extern uint BLOB_0_7__1;
extern uint BLOB_0_9;

extern uint BLOB_0_9__1;
extern uint BLOB_0_A;
extern uint BLOB_0_15;

extern uint BLOB_0_9__2;
extern uint BLOB_0_A__1;
extern uint BLOB_0_15__1;

extern uint BLOB_0_F;

extern uint HEADER_ID_REMOTE_LAST;
extern uint HEADER_ID_SEND;

extern uint START_HEADER_ID;

extern uint UIC_CRC;


//
// sess1pkt7 (recv0042) body msg packet
//
int encode41_sess1pkt7r_recurs3(char *buf, int buf_limit_len){
	struct blob_s blob;
	int buf_len;
	int blob_count;

	memset(buf,0,sizeof(buf));
    buf_len=0;

	blob_count = 5;

    buf_len=make_41cmdencode_recurs(buf, buf_len, blob_count, 0);

    // start_header_id -- blob1
    blob.obj_type = 0;
	blob.obj_index = 0x0A;
    //blob.obj_data = 0x27AAA1B3;
    blob.obj_data = START_HEADER_ID;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // some flag -- blob2
    blob.obj_type = 0;
	blob.obj_index = 0;
    blob.obj_data = 0x02;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // some info -- blob3
    blob.obj_type = 0;
	blob.obj_index = 1;
	blob.obj_data = 0x02;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // sender user uic_crc -- blob4
    blob.obj_type = 0;
	blob.obj_index = 2;
    blob.obj_data = UIC_CRC;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	// 04-03 crypto container -- blob5
    blob.obj_type = 0x04;
	blob.obj_index = 0x03;
    blob.obj_data = 0;
	blob.data_ptr = (int)NEWBLK;
	blob.data_size = NEWBLK_LEN;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	if ( buf_len > buf_limit_len ){
		debuglog("buffer limit overrun\n");
		return -1;
	};

	return buf_len;
};


int encode41_sess1pkt7r_recurs2(char *buf, int buf_limit_len){
	struct blob_s blob;
	int buf_len;
	int blob_count;

	char intbuf[0x1000];
	int intbuf_len;

	memset(buf,0,sizeof(buf));
    buf_len=0;

	blob_count = 2;

    buf_len=make_41cmdencode_recurs(buf, buf_len, blob_count, 0);

    // 00-01: 0x2B obertka body msg with crypto -- blob1
    blob.obj_type = 0;
	blob.obj_index = 1;
    blob.obj_data = 0x2B;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // blob2 ALLOC1 recursive
	intbuf_len=encode41_sess1pkt7r_recurs3(intbuf,sizeof(intbuf));
    blob.obj_type = 0x05;
	blob.obj_index = 0x20;
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


int encode41_sess1pkt7r_recurs(char *buf, int buf_limit_len){
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

    // stage -- blob2
    blob.obj_type = 0;
	blob.obj_index = 3;
	blob.obj_data = get_chatsync_stage();
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // blob3 ALLOC1 recursive 41
	intbuf_len=encode41_sess1pkt7r_recurs2(intbuf,sizeof(intbuf));
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


int encode41_sess1pkt_cmd2Br_msgbody(char *buf, int buf_limit_len){
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
	intbuf_len=encode41_sess1pkt7r_recurs(intbuf,sizeof(intbuf));
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

===
PARAM send040
===
{
04-EFEF: 2 bytes
0000: 51 22                                           | Q"               |

00-00: 02 00 00 00
00-01: 6D 00 00 00
00-02: 64 DF 00 00
05-03: {
00-01: 43 82 D4 50
00-03: 07 00 00 00
04-04: 211 bytes
0000: 41 02 00 01 2B 05 20 41 05 00 0A B3 C3 AA BD 02 | A...+. A........ |
0010: 00 00 02 00 01 02 00 02 C7 B5 DB AD 08 04 03 B2 | ................ |
0020: 01 3F AD D4 0A FE CD B6 BE AD 71 BA 47 6C 18 7A | .?........q.Gl.z |
0030: 0A EA 1D 97 F5 B6 6F 47 D1 42 BC E3 9D AE B7 4C | ......oG.B.....L |
0040: F6 0B 50 DD DC 61 68 68 C7 83 92 09 18 CA 3F 68 | ..P..ahh......?h |
0050: 71 11 B0 3B CF 1E C8 34 9C 25 58 6A A1 62 E2 39 | q..;...4.%Xj.b.9 |
0060: 44 83 29 86 17 53 C6 67 B3 4C 41 E2 88 86 76 61 | D.)..S.g.LA...va |
0070: 35 37 2D FF 3B 9A D2 7D D3 F1 A9 ED EA EC 13 34 | 57-.;..}.......4 |
0080: 7A 34 0A 46 DE 35 D1 F6 F7 55 F7 C0 DD D4 E5 DF | z4.F.5...U...... |
0090: 75 7A 60 31 9B 09 E6 FE FD 7F AD 76 2E 3B DE 15 | uz`1.......v.;.. |
00A0: 4B 00 05 DE D8 A5 B2 05 00 06 9B D0 C0 0B 00 07 | K............... |
00B0: B3 C3 AA BD 02 03 0E 74 68 65 6D 61 67 69 63 66 | .......themagicf |
00C0: 6F 72 79 6F 75 00 00 0F F4 02 00 0A B6 90 ED 24 | oryou..........$ |
00D0: 06 1B 00                                        | ...              |

}
}
===
===
{
00-01: 2B 00 00 00
05-20: {
00-0A: B3 A1 AA 27
00-00: 02 00 00 00
00-01: 02 00 00 00
00-02: C7 DA B6 85
04-03: 178 bytes
0000: 3F AD D4 0A FE CD B6 BE AD 71 BA 47 6C 18 7A 0A | ?........q.Gl.z. |
0010: EA 1D 97 F5 B6 6F 47 D1 42 BC E3 9D AE B7 4C F6 | .....oG.B.....L. |
0020: 0B 50 DD DC 61 68 68 C7 83 92 09 18 CA 3F 68 71 | .P..ahh......?hq |
0030: 11 B0 3B CF 1E C8 34 9C 25 58 6A A1 62 E2 39 44 | ..;...4.%Xj.b.9D |
0040: 83 29 86 17 53 C6 67 B3 4C 41 E2 88 86 76 61 35 | .)..S.g.LA...va5 |
0050: 37 2D FF 3B 9A D2 7D D3 F1 A9 ED EA EC 13 34 7A | 7-.;..}.......4z |
0060: 34 0A 46 DE 35 D1 F6 F7 55 F7 C0 DD D4 E5 DF 75 | 4.F.5...U......u |
0070: 7A 60 31 9B 09 E6 FE FD 7F AD 76 2E 3B DE 15 4B | z`1.......v.;..K |
0080: 00 05 DE D8 A5 B2 05 00 06 9B D0 C0 0B 00 07 B3 | ................ |
0090: C3 AA BD 02 03 0E 74 68 65 6D 61 67 69 63 66 6F | ......themagicfo |
00A0: 72 79 6F 75 00 00 0F F4 02 00 0A B6 90 ED 24 06 | ryou..........$. |
00B0: 1B 00                                           | ..               |

}
}
===

*/

