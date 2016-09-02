//
// pkt cmd24 chatsign
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

extern uint global_unknown_cmd24_signed_id;


extern u8 CHAT_STRING[0x100];
extern u8 CHAT_PEERS_REVERSED[0x100];
extern u8 CREDENTIALS[0x105];
extern uint CREDENTIALS_LEN;
extern u8 NEWBLK[0x1000];
extern uint NEWBLK_LEN;
extern u8 REMOTE_NAME[0x100];

extern uint UIC_CRC;
extern uint BLOB_0_1;
extern uint BLOB_0_A__1;

//
extern uint HEADER_ID_REMOTE_LAST;
extern uint HEADER_ID_SEND;
//


extern uint START_HEADER_ID;


//
// chat init signed packet (newblk1)
// 
int encode41_sess1pkt_cmd24_recurs4(char *buf, int buf_limit_len){
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
    blob.obj_data = 8;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);
	
    // some flag -- blob2
    blob.obj_type = 0;
	blob.obj_index = 1;
    blob.obj_data = 1;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // sender user uic_crc -- blob3
    blob.obj_type = 0;
	blob.obj_index = 2;
    //blob.obj_data = BLOB_0_2__1;
    //blob.obj_data = 0xE9C150A9;
    //blob.obj_data = 0xEDB0C344;
    //blob.obj_data = 0x1E8C1D4C;
    blob.obj_data = UIC_CRC;
	blob.data_ptr = 0;
	blob.data_size = 0;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	// newblk1 -- blob4
    blob.obj_type = 4;
	blob.obj_index = 3;
    blob.obj_data = 0;
	blob.data_ptr = (int)NEWBLK;
	blob.data_size = NEWBLK_LEN;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // blob5 credentials
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


int encode41_sess1pkt_cmd24_recurs3(char *buf, int buf_limit_len){
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
	intbuf_len=encode41_sess1pkt_cmd24_recurs4(intbuf,sizeof(intbuf));
    blob.obj_type = 5;
	blob.obj_index = 0;
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

    // unknown_cmd24_signed_id -- blob3
    blob.obj_type = 0;
	blob.obj_index = 7;
	//blob.obj_data = BLOB_0_7;
    //blob.obj_data = 0x08DD772A;
	//blob.obj_data = 0x710F3804;
	//blob.obj_data = 0x21D598C5;
	blob.obj_data = global_unknown_cmd24_signed_id;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // timestamp in minutes -- blob4
    blob.obj_type = 0;
	blob.obj_index = 9;
	blob.obj_data = time(NULL) / 60;
	blob.data_ptr = 0;
	blob.data_size = 0;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);
	
	if ( buf_len > buf_limit_len ){
		debuglog("buffer limit overrun\n");
		return -1;
	};

	return buf_len;
};




int encode41_sess1pkt_cmd24_recurs2(char *buf, int buf_limit_len){
	struct blob_s blob;
	int buf_len;
	int blob_count;
	u8 str_null[]="";

	//u8 chat_string[]="#xoteg_iam/$xot_iam;4fef7b015cb20ad0";
    //u8 peers[]="xot_iam xoteg_iam";
   
	char intbuf[0x1000];
	int intbuf_len;

	memset(buf,0,sizeof(buf));
    buf_len=0;

	blob_count = 6;

	buf_len=make_41cmdencode_recurs(buf, buf_len, blob_count, 0);

    // chat cmd -- blob1
    blob.obj_type = 0;
	blob.obj_index = 1;
    blob.obj_data = 0x24;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // chat string -- blob2
    blob.obj_type = 3;
	blob.obj_index = 2;
    blob.obj_data = 0;
	blob.data_ptr = (int)CHAT_STRING;
	blob.data_size = strlen(CHAT_STRING)+1;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // some flag -- blob3
    blob.obj_type = 0;
	blob.obj_index = 0x1B;
    blob.obj_data = 7;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // chat peers -- blob4
    blob.obj_type = 3;
	blob.obj_index = 0x12;
    blob.obj_data = 0;
	blob.data_ptr = (int)CHAT_PEERS_REVERSED;
	blob.data_size = strlen(CHAT_PEERS_REVERSED)+1;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);
	
    // null string -- blob5
    blob.obj_type = 3;
	blob.obj_index = 0x1E;
    blob.obj_data = 0;
	blob.data_ptr = (int)str_null;
	blob.data_size = strlen(str_null)+1;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // blob6 recursive 41
	intbuf_len=encode41_sess1pkt_cmd24_recurs3(intbuf,sizeof(intbuf));
    blob.obj_type = 5;
	blob.obj_index = 0x19;
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


int encode41_sess1pkt_cmd24_recurs(char *buf, int buf_limit_len){
	struct blob_s blob;
	int buf_len;
	int blob_count;
    
	char intbuf[0x1000];
	int intbuf_len;

	memset(buf,0,sizeof(buf));
    buf_len=0;

    blob_count = 3;

    buf_len=make_41cmdencode_recurs(buf, buf_len, blob_count, 0);

    // session id -- blob1
    blob.obj_type = 0;
	blob.obj_index = 1;
    //blob.obj_data = BLOB_0_1;
    //blob.obj_data = 0x55829E55;
	//blob.obj_data = 0xCF0522DE;
	//blob.obj_data = 0xBF356579;
	blob.obj_data = get_chatsync_streamid();
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // stage blob -- blob2
    blob.obj_type = 0;
	blob.obj_index = 3;
    //blob.obj_data = 1;
	blob.obj_data = get_chatsync_stage();
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // blob3 ALLOC1 recursive 41
	intbuf_len=encode41_sess1pkt_cmd24_recurs2(intbuf,sizeof(intbuf));
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



int encode41_sess1pkt_cmd24(char *buf, int buf_limit_len){
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
	intbuf_len=encode41_sess1pkt_cmd24_recurs(intbuf,sizeof(intbuf));
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

new chat session init
(signed, newblk1)

20:32:12.127 T#1348 Logger AES dump from 00914C97 len 26E
20:32:12.127 T#1348 Before: 
20:32:12.127 T#1348 00 A6 01 41 04 00 00 02 00 01 6D 00 02 D2 89 02 
20:32:12.127 T#1348 05 03 41 03 00 01 F9 CA D5 F9 0B 00 03 01 04 04 
20:32:12.127 T#1348 CA 04 41 06 00 01 24 03 02 23 74 68 65 6D 61 67 
20:32:12.127 T#1348 69 63 66 6F 72 79 6F 75 2F 24 6E 6F 74 6E 6F 77 
20:32:12.127 T#1348 61 67 61 69 6E 70 6C 65 61 73 65 3B 62 63 35 66 
20:32:12.127 T#1348 66 64 39 32 39 39 31 33 32 65 61 35 00 00 1B 07 
20:32:12.127 T#1348 03 12 6E 6F 74 6E 6F 77 61 67 61 69 6E 70 6C 65 
20:32:12.127 T#1348 61 73 65 20 74 68 65 6D 61 67 69 63 66 6F 72 79 
20:32:12.127 T#1348 6F 75 00 03 1E 00 05 19 41 04 05 00 41 05 00 00 
20:32:12.127 T#1348 08 00 01 01 00 02 CC BA B0 F4 01 04 03 B5 01 64 
20:32:12.127 T#1348 23 CB 39 A8 FF B0 25 ED 88 3D 26 F2 DF F5 DB 3F 
20:32:12.127 T#1348 24 AF 3C A6 9C 00 28 13 24 86 3D 9D 77 55 9B C0 
20:32:12.127 T#1348 D9 3B 56 14 ED E0 49 0B CA E7 46 FA F2 BE 34 D3 
20:32:12.127 T#1348 E8 7B 2E D2 2B 78 D3 4B 25 5C 94 D9 35 57 81 EF 
20:32:12.127 T#1348 25 F6 2A 46 73 0D 64 49 64 81 9C 91 33 C6 72 13 
20:32:12.127 T#1348 5C 72 A0 71 07 0B 99 C4 9F 6F BD C3 F3 65 A9 7B 
20:32:12.127 T#1348 A8 45 4E 4F F0 35 E0 D2 05 EA D6 6E 25 87 E3 8F 
20:32:12.127 T#1348 2E 2F D0 62 AE 90 9A B9 DF 5C FA D8 50 05 45 00 
20:32:12.127 T#1348 05 85 97 EB 9D 05 00 06 8F FE 94 0B 00 07 A9 D7 
20:32:12.127 T#1348 D4 B1 01 03 01 6E 6F 74 6E 6F 77 61 67 61 69 6E 
20:32:12.127 T#1348 70 6C 65 61 73 65 00 00 0A C5 B1 D6 8E 02 06 1B 
20:32:12.127 T#1348 00 00 0B 01 04 04 84 02 00 00 00 01 A7 CF DF F5 
20:32:12.127 T#1348 A9 69 80 2C 56 12 D5 8B 4B B1 6A 51 0B F4 E1 69 
20:32:12.127 T#1348 47 96 89 2D 82 A2 16 B7 19 C9 52 DF 08 84 0D 28 
20:32:12.127 T#1348 04 0F 10 6F 07 D4 FF 3E 64 80 34 36 DC 25 5F 79 
20:32:12.127 T#1348 F1 7F 1C 4C 90 9C 03 E2 EF 9D B9 C6 D9 52 55 D4 
20:32:12.127 T#1348 C0 FE 31 6E 08 EA FA C9 61 BB F8 DA F7 2E 8A 13 
20:32:12.127 T#1348 16 B2 12 7E 17 38 D7 13 2E 85 1D 27 63 71 DD 48 
20:32:12.127 T#1348 A9 95 37 F6 FE 62 76 31 F8 0E 5E 4B 1A 8C C2 F4 
20:32:12.127 T#1348 14 80 5E 96 1C CB 81 E7 DC 5A F5 E7 D8 6D E7 9F 
20:32:12.127 T#1348 F2 AD 77 A1 E1 A4 03 CF 57 41 C6 61 82 D8 BF 24 
20:32:12.127 T#1348 7A 1F C4 23 08 DC C2 5A 63 79 95 FF 0B 3E 1E F8 
20:32:12.127 T#1348 7A 6C 49 05 00 45 5E DD AB 9F 19 F6 50 D1 4A B9 
20:32:12.127 T#1348 02 92 C5 62 6E 27 44 DC 68 06 09 FD 1D 6E C1 C0 
20:32:12.127 T#1348 0F 3D 90 E4 1A F9 DE 46 5B 27 B6 9F 48 AC B4 1A 
20:32:12.127 T#1348 95 92 8C 7D E2 9D A3 A7 C7 06 95 2A FC D3 86 C3 
20:32:12.127 T#1348 46 4E 7E 9F F8 A6 2C E9 5D 94 FC 95 CC C0 83 84 
20:32:12.127 T#1348 C0 40 35 DD A0 72 6B 78 7C 26 3E 68 00 06 01 00 
20:32:12.127 T#1348 07 C5 B1 D6 8E 02 00 09 8F FE 94 0B 0B 4C 
===
PARAM send0013
===
{
00-00: 02 00 00 00
00-01: 6D 00 00 00
00-02: D2 84 00 00
05-03: {
00-01: 79 65 35 BF
00-03: 01 00 00 00
04-04: 586 bytes
0000: 41 06 00 01 24 03 02 23 74 68 65 6D 61 67 69 63 | A...$..#themagic |
0010: 66 6F 72 79 6F 75 2F 24 6E 6F 74 6E 6F 77 61 67 | foryou/$notnowag |
0020: 61 69 6E 70 6C 65 61 73 65 3B 62 63 35 66 66 64 | ainplease;bc5ffd |
0030: 39 32 39 39 31 33 32 65 61 35 00 00 1B 07 03 12 | 9299132ea5...... |
0040: 6E 6F 74 6E 6F 77 61 67 61 69 6E 70 6C 65 61 73 | notnowagainpleas |
0050: 65 20 74 68 65 6D 61 67 69 63 66 6F 72 79 6F 75 | e themagicforyou |
0060: 00 03 1E 00 05 19 41 04 05 00 41 05 00 00 08 00 | ......A...A..... |
0070: 01 01 00 02 CC BA B0 F4 01 04 03 B5 01 64 23 CB | .............d#. |
0080: 39 A8 FF B0 25 ED 88 3D 26 F2 DF F5 DB 3F 24 AF | 9...%..=&....?$. |
0090: 3C A6 9C 00 28 13 24 86 3D 9D 77 55 9B C0 D9 3B | <...(.$.=.wU...; |
00A0: 56 14 ED E0 49 0B CA E7 46 FA F2 BE 34 D3 E8 7B | V...I...F...4..{ |
00B0: 2E D2 2B 78 D3 4B 25 5C 94 D9 35 57 81 EF 25 F6 | ..+x.K%\..5W..%. |
00C0: 2A 46 73 0D 64 49 64 81 9C 91 33 C6 72 13 5C 72 | *Fs.dId...3.r.\r |
00D0: A0 71 07 0B 99 C4 9F 6F BD C3 F3 65 A9 7B A8 45 | .q.....o...e.{.E |
00E0: 4E 4F F0 35 E0 D2 05 EA D6 6E 25 87 E3 8F 2E 2F | NO.5.....n%..../ |
00F0: D0 62 AE 90 9A B9 DF 5C FA D8 50 05 45 00 05 85 | .b.....\..P.E... |
0100: 97 EB 9D 05 00 06 8F FE 94 0B 00 07 A9 D7 D4 B1 | ................ |
0110: 01 03 01 6E 6F 74 6E 6F 77 61 67 61 69 6E 70 6C | ...notnowagainpl |
0120: 65 61 73 65 00 00 0A C5 B1 D6 8E 02 06 1B 00 00 | ease............ |
0130: 0B 01 04 04 84 02 00 00 00 01 A7 CF DF F5 A9 69 | ...............i |
0140: 80 2C 56 12 D5 8B 4B B1 6A 51 0B F4 E1 69 47 96 | .,V...K.jQ...iG. |
0150: 89 2D 82 A2 16 B7 19 C9 52 DF 08 84 0D 28 04 0F | .-......R....(.. |
0160: 10 6F 07 D4 FF 3E 64 80 34 36 DC 25 5F 79 F1 7F | .o...>d.46.%_y.. |
0170: 1C 4C 90 9C 03 E2 EF 9D B9 C6 D9 52 55 D4 C0 FE | .L.........RU... |
0180: 31 6E 08 EA FA C9 61 BB F8 DA F7 2E 8A 13 16 B2 | 1n....a......... |
0190: 12 7E 17 38 D7 13 2E 85 1D 27 63 71 DD 48 A9 95 | .~.8.....'cq.H.. |
01A0: 37 F6 FE 62 76 31 F8 0E 5E 4B 1A 8C C2 F4 14 80 | 7..bv1..^K...... |
01B0: 5E 96 1C CB 81 E7 DC 5A F5 E7 D8 6D E7 9F F2 AD | ^......Z...m.... |
01C0: 77 A1 E1 A4 03 CF 57 41 C6 61 82 D8 BF 24 7A 1F | w.....WA.a...$z. |
01D0: C4 23 08 DC C2 5A 63 79 95 FF 0B 3E 1E F8 7A 6C | .#...Zcy...>..zl |
01E0: 49 05 00 45 5E DD AB 9F 19 F6 50 D1 4A B9 02 92 | I..E^.....P.J... |
01F0: C5 62 6E 27 44 DC 68 06 09 FD 1D 6E C1 C0 0F 3D | .bn'D.h....n...= |
0200: 90 E4 1A F9 DE 46 5B 27 B6 9F 48 AC B4 1A 95 92 | .....F['..H..... |
0210: 8C 7D E2 9D A3 A7 C7 06 95 2A FC D3 86 C3 46 4E | .}.......*....FN |
0220: 7E 9F F8 A6 2C E9 5D 94 FC 95 CC C0 83 84 C0 40 | ~...,.]........@ |
0230: 35 DD A0 72 6B 78 7C 26 3E 68 00 06 01 00 07 C5 | 5..rkx|&>h...... |
0240: B1 D6 8E 02 00 09 8F FE 94 0B                   | ..........       |

}
}
===

===
{
00-01: 24 00 00 00
03-02: "#themagicforyou/$notnowagainplease;bc5ffd9299132ea5"
00-1B: 07 00 00 00
03-12: "notnowagainplease themagicforyou"
03-1E: ""
05-19: {
05-00: {
00-00: 08 00 00 00
00-01: 01 00 00 00
00-02: 4C 1D 8C 1E
04-03: 181 bytes
0000: 64 23 CB 39 A8 FF B0 25 ED 88 3D 26 F2 DF F5 DB | d#.9...%..=&.... |
0010: 3F 24 AF 3C A6 9C 00 28 13 24 86 3D 9D 77 55 9B | ?$.<...(.$.=.wU. |
0020: C0 D9 3B 56 14 ED E0 49 0B CA E7 46 FA F2 BE 34 | ..;V...I...F...4 |
0030: D3 E8 7B 2E D2 2B 78 D3 4B 25 5C 94 D9 35 57 81 | ..{..+x.K%\..5W. |
0040: EF 25 F6 2A 46 73 0D 64 49 64 81 9C 91 33 C6 72 | .%.*Fs.dId...3.r |
0050: 13 5C 72 A0 71 07 0B 99 C4 9F 6F BD C3 F3 65 A9 | .\r.q.....o...e. |
0060: 7B A8 45 4E 4F F0 35 E0 D2 05 EA D6 6E 25 87 E3 | {.ENO.5.....n%.. |
0070: 8F 2E 2F D0 62 AE 90 9A B9 DF 5C FA D8 50 05 45 | ../.b.....\..P.E |
0080: 00 05 85 97 EB 9D 05 00 06 8F FE 94 0B 00 07 A9 | ................ |
0090: D7 D4 B1 01 03 01 6E 6F 74 6E 6F 77 61 67 61 69 | ......notnowagai |
00A0: 6E 70 6C 65 61 73 65 00 00 0A C5 B1 D6 8E 02 06 | nplease......... |
00B0: 1B 00 00 0B 01                                  | .....            |

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
00-07: C5 98 D5 21
00-09: 0F 3F 65 01
}
}
===

===
SIGNED TEXT
===
recovered signed data:
Len: 0x000000A0
6A 6B 63 02 9A 57 6C 59 EC 36 22 B6 15 7B BB FE  ; jkc  WlY 6"  {  
 71 18 6F F3 14 23 74 68 65 6D 61 67 69 63 66 6F  ; q o  #themagicfo
 72 79 6F 75 2F 24 6E 6F 74 6E 6F 77 61 67 61 69  ; ryou/$notnowagai
 6E 70 6C 65 61 73 65 3B 62 63 35 66 66 64 39 32  ; nplease;bc5ffd92
 39 39 31 33 32 65 61 35 41 09 00 00 01 04 03 1B  ; 99132ea5A       
 65 03 23 5A 28 22 17 37 01 C0 A8 01 87 5B 73 9D  ; e #Z(" 7     [s 
 37 EB 8F 9C 55 B2 41 2C 15 5B 73 00 05 85 97 EB  ; 7   U A, [s     
 9D 05 00 06 8F FE 94 0B 00 07 A9 D7 D4 B1 01 03  ;                 
 01 6E 6F 74 6E 6F 77 61 67 61 69 6E 70 6C 65 61  ;  notnowagainplea
 73 65 00 00 0A C5 B1 D6 8E 02 06 1B 00 00 0B 01  ; se              
 
{
00-00: 01 00 00 00
04-03: 27 bytes
0000: 65 03 23 5A 28 22 17 37 01 C0 A8 01 87 5B 73 9D | e.#Z(".7.....[s. |
0010: 37 EB 8F 9C 55 B2 41 2C 15 5B 73                | 7...U.A,.[s      |

00-05: 85 CB BA 53
00-06: 0F 3F 65 01
00-07: A9 2B 35 16
03-01: "notnowagainplease"
00-0A: C5 98 D5 21
06-1B: 
00-0B: 01 00 00 00
}
===

*/
