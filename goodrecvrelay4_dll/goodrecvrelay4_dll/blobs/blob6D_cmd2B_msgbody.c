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
// sess1pkt7 (send0013) body msg packet
//
int encode41_sess1pkt7_recurs3(char *buf, int buf_limit_len){
	struct blob_s blob;
	int buf_len;
	int blob_count;

	memset(buf,0,sizeof(buf));
    buf_len=0;

	blob_count = 5;

    buf_len=make_41cmdencode_recurs(buf, buf_len, blob_count, 0);

    // start_header_id + 1 -- blob1
    blob.obj_type = 0;
	blob.obj_index = 0x0A;
    blob.obj_data = START_HEADER_ID + 1;
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
	blob.obj_data = 0x01;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // sender user uic_crc -- blob4
    blob.obj_type = 0;
	blob.obj_index = 2;
    //blob.obj_data = 0xEDB0C344;
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


int encode41_sess1pkt7_recurs2(char *buf, int buf_limit_len){
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
	intbuf_len=encode41_sess1pkt7_recurs3(intbuf,sizeof(intbuf));
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


int encode41_sess1pkt7_recurs(char *buf, int buf_limit_len){
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
	intbuf_len=encode41_sess1pkt7_recurs2(intbuf,sizeof(intbuf));
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


int encode41_sess1pkt_cmd2B(char *buf, int buf_limit_len){
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
	intbuf_len=encode41_sess1pkt7_recurs(intbuf,sizeof(intbuf));
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

sess1pkt7 (send0013) body msg packet

20:32:12.518 T#1348 Logger AES dump from 00914C97 len EF
20:32:12.518 T#1348 Before: 
20:32:12.518 T#1348 00 A6 01 41 05 04 EF DF 03 03 65 A3 E9 00 00 02 
20:32:12.518 T#1348 00 01 6D 00 02 F1 F5 01 05 03 41 03 00 01 F9 CA 
20:32:12.518 T#1348 D5 F9 0B 00 03 04 04 04 C3 01 41 02 00 01 2B 05 
20:32:12.518 T#1348 20 41 05 00 0A AA D7 D4 B1 01 00 00 02 00 01 01 
20:32:12.518 T#1348 00 02 CC BA B0 F4 01 04 03 A2 01 89 2A B1 74 0B 
20:32:12.518 T#1348 02 4A BF 7A 47 EE CA CF BA 3B 49 87 18 14 17 DA 
20:32:12.518 T#1348 3C 80 87 76 7C 53 D7 52 60 E4 0D 72 1C 13 AA D1 
20:32:12.518 T#1348 3C 16 F4 B3 08 08 47 5B 60 FF 37 7E 51 15 C3 61 
20:32:12.518 T#1348 50 53 16 12 28 A5 59 FA D5 31 9D 22 45 8D EE F3 
20:32:12.518 T#1348 59 FA 57 F7 EC 79 EF 13 F9 CE 79 11 2F BE 11 4D 
20:32:12.518 T#1348 C6 46 7F 58 EB 2C A4 95 E9 A5 56 F8 EA B5 7D 2E 
20:32:12.518 T#1348 E3 40 97 C8 2D 7D 42 86 9D 67 D6 3D 3B 3E 37 80 
20:32:12.518 T#1348 54 7D DA AF 31 6E 23 43 01 87 9E 00 05 8B 97 EB 
20:32:12.518 T#1348 9D 05 00 06 8F FE 94 0B 00 07 AA D7 D4 B1 01 00 
20:32:12.518 T#1348 44 01 03 02 74 65 73 74 33 33 34 35 00 B7 FB 
===
PARAM send0028
===
{
04-EFEF: 3 bytes
0000: 65 A3 E9                                        | e..              |

00-00: 02 00 00 00
00-01: 6D 00 00 00
00-02: F1 7A 00 00
05-03: {
00-01: 79 65 35 BF
00-03: 04 00 00 00
04-04: 195 bytes
0000: 41 02 00 01 2B 05 20 41 05 00 0A AA D7 D4 B1 01 | A...+. A........ |
0010: 00 00 02 00 01 01 00 02 CC BA B0 F4 01 04 03 A2 | ................ |
0020: 01 89 2A B1 74 0B 02 4A BF 7A 47 EE CA CF BA 3B | ..*.t..J.zG....; |
0030: 49 87 18 14 17 DA 3C 80 87 76 7C 53 D7 52 60 E4 | I.....<..v|S.R`. |
0040: 0D 72 1C 13 AA D1 3C 16 F4 B3 08 08 47 5B 60 FF | .r....<.....G[`. |
0050: 37 7E 51 15 C3 61 50 53 16 12 28 A5 59 FA D5 31 | 7~Q..aPS..(.Y..1 |
0060: 9D 22 45 8D EE F3 59 FA 57 F7 EC 79 EF 13 F9 CE | ."E...Y.W..y.... |
0070: 79 11 2F BE 11 4D C6 46 7F 58 EB 2C A4 95 E9 A5 | y./..M.F.X.,.... |
0080: 56 F8 EA B5 7D 2E E3 40 97 C8 2D 7D 42 86 9D 67 | V...}..@..-}B..g |
0090: D6 3D 3B 3E 37 80 54 7D DA AF 31 6E 23 43 01 87 | .=;>7.T}..1n#C.. |
00A0: 9E 00 05 8B 97 EB 9D 05 00 06 8F FE 94 0B 00 07 | ................ |
00B0: AA D7 D4 B1 01 00 44 01 03 02 74 65 73 74 33 33 | ......D...test33 |
00C0: 34 35 00                                        | 45.              |

}
}
===

===
{
00-01: 2B 00 00 00
05-20: {
00-0A: AA 2B 35 16
00-00: 02 00 00 00
00-01: 01 00 00 00
00-02: 4C 1D 8C 1E
04-03: 162 bytes
0000: 89 2A B1 74 0B 02 4A BF 7A 47 EE CA CF BA 3B 49 | .*.t..J.zG....;I |
0010: 87 18 14 17 DA 3C 80 87 76 7C 53 D7 52 60 E4 0D | .....<..v|S.R`.. |
0020: 72 1C 13 AA D1 3C 16 F4 B3 08 08 47 5B 60 FF 37 | r....<.....G[`.7 |
0030: 7E 51 15 C3 61 50 53 16 12 28 A5 59 FA D5 31 9D | ~Q..aPS..(.Y..1. |
0040: 22 45 8D EE F3 59 FA 57 F7 EC 79 EF 13 F9 CE 79 | "E...Y.W..y....y |
0050: 11 2F BE 11 4D C6 46 7F 58 EB 2C A4 95 E9 A5 56 | ./..M.F.X.,....V |
0060: F8 EA B5 7D 2E E3 40 97 C8 2D 7D 42 86 9D 67 D6 | ...}..@..-}B..g. |
0070: 3D 3B 3E 37 80 54 7D DA AF 31 6E 23 43 01 87 9E | =;>7.T}..1n#C... |
0080: 00 05 8B 97 EB 9D 05 00 06 8F FE 94 0B 00 07 AA | ................ |
0090: D7 D4 B1 01 00 44 01 03 02 74 65 73 74 33 33 34 | .....D...test334 |
00A0: 35 00                                           | 5.               |

}
}
===

===
SIGNED TEXT
===
recovered signed data:
Len: 0x0000008D
6A 6B 63 02 9A 57 6C 59 EC 36 22 B6 15 7B BB FE  ; jkc  WlY 6"  {  
 71 18 6F F3 14 23 74 68 65 6D 61 67 69 63 66 6F  ; q o  #themagicfo
 72 79 6F 75 2F 24 6E 6F 74 6E 6F 77 61 67 61 69  ; ryou/$notnowagai
 6E 70 6C 65 61 73 65 3B 62 63 35 66 66 64 39 32  ; nplease;bc5ffd92
 39 39 31 33 32 65 61 35 41 07 00 00 03 04 03 1B  ; 99132ea5A       
 65 03 23 5A 28 22 17 37 01 C0 A8 01 87 5B 73 9D  ; e #Z(" 7     [s 
 37 EB 8F 9C 55 B2 41 2C 15 5B 73 00 05 8B 97 EB  ; 7   U A, [s     
 9D 05 00 06 8F FE 94 0B 00 07 AA D7 D4 B1 01 00  ;                 
 44 01 03 02 74 65 73 74 33 33 34 35 00 
{
00-00: 03 00 00 00
04-03: 27 bytes
0000: 65 03 23 5A 28 22 17 37 01 C0 A8 01 87 5B 73 9D | e.#Z(".7.....[s. |
0010: 37 EB 8F 9C 55 B2 41 2C 15 5B 73                | 7...U.A,.[s      |

00-05: 8B CB BA 53
00-06: 0F 3F 65 01
00-07: AA 2B 35 16
00-44: 01 00 00 00
03-02: "test3345"
}
===

*/

