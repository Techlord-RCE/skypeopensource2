//
// session 6 pkt
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

extern uint UIC_CRC;
extern uint BLOB_0_1;
extern uint BLOB_0_A__1;

extern uint HEADER_ID_REMOTE_LAST;
extern uint HEADER_ID_SEND;

extern uint global_unknown_cmd2A_signed_id;

extern uint pkt_cmd2A_BLOB_00_00;

extern uint global_msg_time_sec;
extern uint global_msg_time_min;


//
// newblk2 pkt (headers sign)
//
int encode41_sess1pkt_cmd2A_recurs4(char *buf, int buf_limit_len){
	struct blob_s blob;
	int buf_len;
	int blob_count;

	memset(buf,0,sizeof(buf));
    buf_len=0;

	blob_count = 5;

    buf_len=make_41cmdencode_recurs(buf, buf_len, blob_count, 0);

    // some flag -- blob1 
    blob.obj_type = 0;
	blob.obj_index = 0;
	blob.obj_data = pkt_cmd2A_BLOB_00_00;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // some flag2 -- blob2
    blob.obj_type = 0;
	blob.obj_index = 1;
    blob.obj_data = 1;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);
	
    // my skype uic_crc -- blob3
    blob.obj_type = 0;
	blob.obj_index = 2;
    blob.obj_data = UIC_CRC;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // newblk2 -- blob4
    blob.obj_type = 4;
	blob.obj_index = 3;
    blob.obj_data = 0;
	blob.data_ptr = (int)NEWBLK;
	blob.data_size = NEWBLK_LEN;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);
	
    // credentials -- blob5
    blob.obj_type = 4;
	blob.obj_index = 4;
    blob.obj_data = 0;
	blob.data_ptr = (int)CREDENTIALS;
	blob.data_size = CREDENTIALS_LEN;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);
	
	if ( buf_len > buf_limit_len ){
		debuglog("buffer limit overrun\n");
		return -1;
	};

	return buf_len;
};



int encode41_sess1pkt_cmd2A_recurs3(char *buf, int buf_limit_len){
	struct blob_s blob;
	int buf_len;
    int blob_count;

	char intbuf[0x1000];
	int intbuf_len;

	memset(buf,0,sizeof(buf));
    buf_len=0;

	blob_count = 4;

    buf_len=make_41cmdencode_recurs(buf, buf_len, blob_count, 0);

    // blob1 recursive 41
	intbuf_len=encode41_sess1pkt_cmd2A_recurs4(intbuf,sizeof(intbuf));	
    blob.obj_type = 5;
	blob.obj_index = 2;
    blob.obj_data = 0;
	blob.data_ptr = (int)intbuf;
	blob.data_size = intbuf_len;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // some flag -- blob2
    blob.obj_type = 0;
	blob.obj_index = 6;
    blob.obj_data = 1;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);
	
    // some unknown header, yet in newblk2 -- blob3
    blob.obj_type = 0;
	blob.obj_index = 7;
    blob.obj_data = global_unknown_cmd2A_signed_id;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);
	
    // timestamp in minutes -- blob4
    blob.obj_type = 0;
	blob.obj_index = 9;
	//blob.obj_data = time(NULL) / 60;
	blob.obj_data = global_msg_time_min;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);
	
	if ( buf_len > buf_limit_len ){
		debuglog("buffer limit overrun\n");
		return -1;
	};

	return buf_len;
};



int encode41_sess1pkt_cmd2A_recurs2(char *buf, int buf_limit_len){
	struct blob_s blob;
	int buf_len;
	int blob_count;
    
	char intbuf[0x1000];
	int intbuf_len;

	memset(buf,0,sizeof(buf));
    buf_len=0;

	blob_count = 2;

    buf_len=make_41cmdencode_recurs(buf, buf_len, blob_count, 0);

    // ChatManager cmd, signed headers -- blob1
    blob.obj_type = 0;
	blob.obj_index = 1;
    blob.obj_data = 0x2A;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // recursive 41 -- blob2
	intbuf_len=encode41_sess1pkt_cmd2A_recurs3(intbuf,sizeof(intbuf));
    blob.obj_type = 5;
	blob.obj_index = 0x18;
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



int encode41_sess1pkt_cmd2A_recurs(char *buf, int buf_limit_len){
	struct blob_s blob;
	int buf_len;
	int blob_count;

	char intbuf[0x1000];
	int intbuf_len;

	memset(buf,0,sizeof(buf));
    buf_len=0;

    blob_count = 3;

    buf_len=make_41cmdencode_recurs(buf, buf_len, blob_count, 0);

    // our local session id -- blob1
    blob.obj_type = 0;
	blob.obj_index = 1;
	blob.obj_data = get_chatsync_streamid();
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // stage blob -- blob
    blob.obj_type = 0;
	blob.obj_index = 3;
    //blob.obj_data = 2;
	blob.obj_data = get_chatsync_stage();
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // ALLOC1 recursive 41 -- blob3
	intbuf_len=encode41_sess1pkt_cmd2A_recurs2(intbuf,sizeof(intbuf));
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


int encode41_sess1pkt_cmd2A(char *buf, int buf_limit_len){
	struct blob_s blob;
	uint session_id;
	uint session_cmd;
	int buf_len;
	int blob_count;
	
	char intbuf[0x1000];
	int intbuf_len;

	session_id=00;
	session_cmd=0xA6;

	blob_count=4;

	memset(buf,0,sizeof(buf));
    buf_len=0;
    buf_len=make_41cmdencodeA6(buf, buf_len, blob_count, session_id, session_cmd, 0);

	// type of session_cmd -- blob1
    blob.obj_type = 0;
	blob.obj_index = 0;
    blob.obj_data = 0x02;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);
	
    // session_cmd command -- blob2
    blob.obj_type = 0;
	blob.obj_index = 1;
    blob.obj_data = 0x6D;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // session_cmd uniq_send_id -- blob3
    blob.obj_type = 0;
	blob.obj_index = 2;
	blob.obj_data = get_cmdid_seqnum();
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // ALLOC1 recursive -- blob4
	intbuf_len=encode41_sess1pkt_cmd2A_recurs(intbuf,sizeof(intbuf));
    blob.obj_type = 5;
	blob.obj_index = 0x03;
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

new chat headers sign pkt
(signed headers, newblk2)

20:32:12.284 T#1348 Logger AES dump from 00914C97 len 205
20:32:12.284 T#1348 Before: 
20:32:12.284 T#1348 00 A6 01 41 05 04 EF DF 03 02 8C 8A 00 00 02 00 
20:32:12.284 T#1348 01 6D 00 02 CD DC 03 05 03 41 03 00 01 F9 CA D5 
20:32:12.284 T#1348 F9 0B 00 03 02 04 04 DA 03 41 02 00 01 2A 05 18 
20:32:12.284 T#1348 41 04 05 02 41 05 00 00 08 00 01 01 00 02 CC BA 
20:32:12.284 T#1348 B0 F4 01 04 03 A4 01 5B 68 B0 EE F1 B4 CF 64 17 
20:32:12.284 T#1348 C6 4E 1B FD F4 0A 13 AE 3D 5A 2E 60 21 AE 9C AD 
20:32:12.284 T#1348 2E 65 BE 58 95 3B 80 56 98 21 ED BC 15 AC F4 6C 
20:32:12.284 T#1348 3D 9B F9 A7 72 E4 A2 0D E1 15 9B AD E4 A5 31 28 
20:32:12.284 T#1348 A3 1E D4 B8 1F 90 46 48 5B CD 44 02 0A 3C 0E E5 
20:32:12.284 T#1348 AE 69 4E AA BE BA 4C FA A4 31 39 35 D4 55 FA D9 
20:32:12.284 T#1348 48 30 15 D7 56 C5 FE D5 B0 3F 89 36 55 A6 C8 9E 
20:32:12.284 T#1348 6A C6 94 C4 19 AB 1E 19 C1 AA 9D 59 66 A2 21 F8 
20:32:12.284 T#1348 CA 50 B2 AB A2 66 7C 00 05 85 97 EB 9D 05 00 06 
20:32:12.284 T#1348 8F FE 94 0B 00 07 A8 D7 D4 B1 01 03 0E 00 00 0F 
20:32:12.284 T#1348 00 00 0A A2 92 BA A0 04 06 1B 00 04 04 84 02 00 
20:32:12.284 T#1348 00 00 01 A7 CF DF F5 A9 69 80 2C 56 12 D5 8B 4B 
20:32:12.284 T#1348 B1 6A 51 0B F4 E1 69 47 96 89 2D 82 A2 16 B7 19 
20:32:12.284 T#1348 C9 52 DF 08 84 0D 28 04 0F 10 6F 07 D4 FF 3E 64 
20:32:12.284 T#1348 80 34 36 DC 25 5F 79 F1 7F 1C 4C 90 9C 03 E2 EF 
20:32:12.284 T#1348 9D B9 C6 D9 52 55 D4 C0 FE 31 6E 08 EA FA C9 61 
20:32:12.284 T#1348 BB F8 DA F7 2E 8A 13 16 B2 12 7E 17 38 D7 13 2E 
20:32:12.284 T#1348 85 1D 27 63 71 DD 48 A9 95 37 F6 FE 62 76 31 F8 
20:32:12.284 T#1348 0E 5E 4B 1A 8C C2 F4 14 80 5E 96 1C CB 81 E7 DC 
20:32:12.284 T#1348 5A F5 E7 D8 6D E7 9F F2 AD 77 A1 E1 A4 03 CF 57 
20:32:12.284 T#1348 41 C6 61 82 D8 BF 24 7A 1F C4 23 08 DC C2 5A 63 
20:32:12.284 T#1348 79 95 FF 0B 3E 1E F8 7A 6C 49 05 00 45 5E DD AB 
20:32:12.284 T#1348 9F 19 F6 50 D1 4A B9 02 92 C5 62 6E 27 44 DC 68 
20:32:12.284 T#1348 06 09 FD 1D 6E C1 C0 0F 3D 90 E4 1A F9 DE 46 5B 
20:32:12.284 T#1348 27 B6 9F 48 AC B4 1A 95 92 8C 7D E2 9D A3 A7 C7 
20:32:12.284 T#1348 06 95 2A FC D3 86 C3 46 4E 7E 9F F8 A6 2C E9 5D 
20:32:12.284 T#1348 94 FC 95 CC C0 83 84 C0 40 35 DD A0 72 6B 78 7C 
20:32:12.284 T#1348 26 3E 68 00 06 01 00 07 A2 92 BA A0 04 00 09 8F 
20:32:12.284 T#1348 FE 94 0B 3A CD 
===
PARAM send0020
===
{
04-EFEF: 2 bytes
0000: 8C 8A                                           | ..               |

00-00: 02 00 00 00
00-01: 6D 00 00 00
00-02: 4D EE 00 00
05-03: {
00-01: 79 65 35 BF
00-03: 02 00 00 00
04-04: 474 bytes
0000: 41 02 00 01 2A 05 18 41 04 05 02 41 05 00 00 08 | A...*..A...A.... |
0010: 00 01 01 00 02 CC BA B0 F4 01 04 03 A4 01 5B 68 | ..............[h |
0020: B0 EE F1 B4 CF 64 17 C6 4E 1B FD F4 0A 13 AE 3D | .....d..N......= |
0030: 5A 2E 60 21 AE 9C AD 2E 65 BE 58 95 3B 80 56 98 | Z.`!....e.X.;.V. |
0040: 21 ED BC 15 AC F4 6C 3D 9B F9 A7 72 E4 A2 0D E1 | !.....l=...r.... |
0050: 15 9B AD E4 A5 31 28 A3 1E D4 B8 1F 90 46 48 5B | .....1(......FH[ |
0060: CD 44 02 0A 3C 0E E5 AE 69 4E AA BE BA 4C FA A4 | .D..<...iN...L.. |
0070: 31 39 35 D4 55 FA D9 48 30 15 D7 56 C5 FE D5 B0 | 195.U..H0..V.... |
0080: 3F 89 36 55 A6 C8 9E 6A C6 94 C4 19 AB 1E 19 C1 | ?.6U...j........ |
0090: AA 9D 59 66 A2 21 F8 CA 50 B2 AB A2 66 7C 00 05 | ..Yf.!..P...f|.. |
00A0: 85 97 EB 9D 05 00 06 8F FE 94 0B 00 07 A8 D7 D4 | ................ |
00B0: B1 01 03 0E 00 00 0F 00 00 0A A2 92 BA A0 04 06 | ................ |
00C0: 1B 00 04 04 84 02 00 00 00 01 A7 CF DF F5 A9 69 | ...............i |
00D0: 80 2C 56 12 D5 8B 4B B1 6A 51 0B F4 E1 69 47 96 | .,V...K.jQ...iG. |
00E0: 89 2D 82 A2 16 B7 19 C9 52 DF 08 84 0D 28 04 0F | .-......R....(.. |
00F0: 10 6F 07 D4 FF 3E 64 80 34 36 DC 25 5F 79 F1 7F | .o...>d.46.%_y.. |
0100: 1C 4C 90 9C 03 E2 EF 9D B9 C6 D9 52 55 D4 C0 FE | .L.........RU... |
0110: 31 6E 08 EA FA C9 61 BB F8 DA F7 2E 8A 13 16 B2 | 1n....a......... |
0120: 12 7E 17 38 D7 13 2E 85 1D 27 63 71 DD 48 A9 95 | .~.8.....'cq.H.. |
0130: 37 F6 FE 62 76 31 F8 0E 5E 4B 1A 8C C2 F4 14 80 | 7..bv1..^K...... |
0140: 5E 96 1C CB 81 E7 DC 5A F5 E7 D8 6D E7 9F F2 AD | ^......Z...m.... |
0150: 77 A1 E1 A4 03 CF 57 41 C6 61 82 D8 BF 24 7A 1F | w.....WA.a...$z. |
0160: C4 23 08 DC C2 5A 63 79 95 FF 0B 3E 1E F8 7A 6C | .#...Zcy...>..zl |
0170: 49 05 00 45 5E DD AB 9F 19 F6 50 D1 4A B9 02 92 | I..E^.....P.J... |
0180: C5 62 6E 27 44 DC 68 06 09 FD 1D 6E C1 C0 0F 3D | .bn'D.h....n...= |
0190: 90 E4 1A F9 DE 46 5B 27 B6 9F 48 AC B4 1A 95 92 | .....F['..H..... |
01A0: 8C 7D E2 9D A3 A7 C7 06 95 2A FC D3 86 C3 46 4E | .}.......*....FN |
01B0: 7E 9F F8 A6 2C E9 5D 94 FC 95 CC C0 83 84 C0 40 | ~...,.]........@ |
01C0: 35 DD A0 72 6B 78 7C 26 3E 68 00 06 01 00 07 A2 | 5..rkx|&>h...... |
01D0: 92 BA A0 04 00 09 8F FE 94 0B                   | ..........       |

}
}
===

===
{
00-01: 2A 00 00 00
05-18: {
05-02: {
00-00: 08 00 00 00
00-01: 01 00 00 00
00-02: 4C 1D 8C 1E
04-03: 164 bytes
0000: 5B 68 B0 EE F1 B4 CF 64 17 C6 4E 1B FD F4 0A 13 | [h.....d..N..... |
0010: AE 3D 5A 2E 60 21 AE 9C AD 2E 65 BE 58 95 3B 80 | .=Z.`!....e.X.;. |
0020: 56 98 21 ED BC 15 AC F4 6C 3D 9B F9 A7 72 E4 A2 | V.!.....l=...r.. |
0030: 0D E1 15 9B AD E4 A5 31 28 A3 1E D4 B8 1F 90 46 | .......1(......F |
0040: 48 5B CD 44 02 0A 3C 0E E5 AE 69 4E AA BE BA 4C | H[.D..<...iN...L |
0050: FA A4 31 39 35 D4 55 FA D9 48 30 15 D7 56 C5 FE | ..195.U..H0..V.. |
0060: D5 B0 3F 89 36 55 A6 C8 9E 6A C6 94 C4 19 AB 1E | ..?.6U...j...... |
0070: 19 C1 AA 9D 59 66 A2 21 F8 CA 50 B2 AB A2 66 7C | ....Yf.!..P...f| |
0080: 00 05 85 97 EB 9D 05 00 06 8F FE 94 0B 00 07 A8 | ................ |
0090: D7 D4 B1 01 03 0E 00 00 0F 00 00 0A A2 92 BA A0 | ................ |
00A0: 04 06 1B 00                                     | ....             |

04-04: 260 bytes
0000: 00 00 00 01 A7 CF DF F5 A9 69 80 2C 56 12 D5 8B | .........i.,V... |
0010: 4B B1 6A 51 0B F4 E1 69 47 96 89 2D 82 A2 16 B7 | K.jQ...iG..-.... |
0020: 19 C9 52 DF 08 84 0D 28 04 0F 10 6F 07 D4 FF 3E | ..R....(...o...> |
0030: 64 80 34 36 DC 25 5F 79 F1 7F 1C 4C 90 9C 03 E2 | d.46.%_y...L.... |
0040: EF 9D B9 C6 D9 52 55 D4 C0 FE 31 6E 08 EA FA C9 | .....RU...1n.... |
0050: 61 BB F8 DA F7 2E 8A 13 16 B2 12 7E 17 38 D7 13 | a..........~.8.. |
0060: 2E 85 1D 27 63 71 DD 48 A9 95 37 F6 FE 62 76 31 | ...'cq.H..7..bv1 |
0070: F8 0E 5E 4B 1A 8C C2 F4 14 80 5E 96 1C CB 81 E7 | ..^K......^..... |
0080: DC 5A F5 E7 D8 6D E7 9F F2 AD 77 A1 E1 A4 03 CF | .Z...m....w..... |
0090: 57 41 C6 61 82 D8 BF 24 7A 1F C4 23 08 DC C2 5A | WA.a...$z..#...Z |
00A0: 63 79 95 FF 0B 3E 1E F8 7A 6C 49 05 00 45 5E DD | cy...>..zlI..E^. |
00B0: AB 9F 19 F6 50 D1 4A B9 02 92 C5 62 6E 27 44 DC | ....P.J....bn'D. |
00C0: 68 06 09 FD 1D 6E C1 C0 0F 3D 90 E4 1A F9 DE 46 | h....n...=.....F |
00D0: 5B 27 B6 9F 48 AC B4 1A 95 92 8C 7D E2 9D A3 A7 | ['..H......}.... |
00E0: C7 06 95 2A FC D3 86 C3 46 4E 7E 9F F8 A6 2C E9 | ...*....FN~...,. |
00F0: 5D 94 FC 95 CC C0 83 84 C0 40 35 DD A0 72 6B 78 | ]........@5..rkx |
0100: 7C 26 3E 68                                     | |&>h             |

}
00-06: 01 00 00 00
00-07: 22 89 0E 44
00-09: 0F 3F 65 01
}
}
===

===
SIGNED TEXT
===
recovered signed data:
Len: 0x0000008F
6A 6B 63 02 9A 57 6C 59 EC 36 22 B6 15 7B BB FE  ; jkc  WlY 6"  {  
 71 18 6F F3 14 23 74 68 65 6D 61 67 69 63 66 6F  ; q o  #themagicfo
 72 79 6F 75 2F 24 6E 6F 74 6E 6F 77 61 67 61 69  ; ryou/$notnowagai
 6E 70 6C 65 61 73 65 3B 62 63 35 66 66 64 39 32  ; nplease;bc5ffd92
 39 39 31 33 32 65 61 35 41 09 00 00 04 04 03 1B  ; 99132ea5A       
 65 03 23 5A 28 22 17 37 01 C0 A8 01 87 5B 73 9D  ; e #Z(" 7     [s 
 37 EB 8F 9C 55 B2 41 2C 15 5B 73 00 05 85 97 EB  ; 7   U A, [s     
 9D 05 00 06 8F FE 94 0B 00 07 A8 D7 D4 B1 01 03  ;                 
 0E 00 00 0F 00 00 0A A2 92 BA A0 04 06 1B 00 
{
00-00: 04 00 00 00
04-03: 27 bytes
0000: 65 03 23 5A 28 22 17 37 01 C0 A8 01 87 5B 73 9D | e.#Z(".7.....[s. |
0010: 37 EB 8F 9C 55 B2 41 2C 15 5B 73                | 7...U.A,.[s      |

00-05: 85 CB BA 53
00-06: 0F 3F 65 01
00-07: A8 2B 35 16
03-0E: ""
00-0F: 00 00 00 00
00-0A: 22 89 0E 44
06-1B: 
}
===

00-05: 85 CB BA 53
00-06: 0F 3F 65 01
^^ time

00-07: A8 2B 35 16
^^ (start header id - 1)

00-0A: 22 89 0E 44
^^ unknown_cmd2A_signed_id
===

*/
