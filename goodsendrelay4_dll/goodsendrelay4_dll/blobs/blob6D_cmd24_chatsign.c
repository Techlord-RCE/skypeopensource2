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
extern u8 CHAT_PEERS[0x100];

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

extern uint pkt_cmd24_BLOB_00_1B;
extern uint pkt_cmd24_BLOB_00_00;

extern uint global_msg_time_sec;
extern uint global_msg_time_min;


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
    blob.obj_data = pkt_cmd24_BLOB_00_00;
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
	blob.obj_data = global_unknown_cmd24_signed_id;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // timestamp in minutes -- blob4
    blob.obj_type = 0;
	blob.obj_index = 9;
	//blob.obj_data = time(NULL) / 60;
	//blob.obj_data = 0x0171710D;
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
    blob.obj_data = pkt_cmd24_BLOB_00_1B;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // chat peers -- blob4
    blob.obj_type = 3;
	blob.obj_index = 0x12;
    blob.obj_data = 0;
	blob.data_ptr = (int)CHAT_PEERS;
	blob.data_size = strlen(CHAT_PEERS)+1;
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

===
PARAM send012
===
{
00-00: 02 00 00 00
00-01: 6D 00 00 00
00-02: 87 DA 00 00
05-03: {
00-01: 1B 75 E1 D3
00-03: 01 00 00 00
04-04: 582 bytes
0000: 41 06 00 01 24 03 02 23 6E 6F 74 6E 6F 77 61 67 | A...$..#notnowag |
0010: 61 69 6E 70 6C 65 61 73 65 2F 24 74 68 65 6D 61 | ainplease/$thema |
0020: 67 69 63 66 6F 72 79 6F 75 3B 38 63 34 39 37 63 | gicforyou;8c497c |
0030: 65 37 32 63 62 64 31 65 34 65 00 00 1B 0A 03 12 | e72cbd1e4e...... |
0040: 6E 6F 74 6E 6F 77 61 67 61 69 6E 70 6C 65 61 73 | notnowagainpleas |
0050: 65 20 74 68 65 6D 61 67 69 63 66 6F 72 79 6F 75 | e themagicforyou |
0060: 00 03 1E 00 05 19 41 04 05 00 41 05 00 00 0B 00 | ......A...A..... |
0070: 01 01 00 02 81 CD D8 0C 04 03 B2 01 2E BB 9C 3A | ...............: |
0080: E6 7E 6B E0 22 AE BC 95 4A EB B4 90 C0 CB AE 3E | .~k."...J......> |
0090: BD 81 20 13 A2 2E C3 F5 40 6F 16 1B D6 64 E5 08 | .. .....@o...d.. |
00A0: F1 E0 B7 AF 0C 64 BB DD 28 D8 E6 07 21 11 C1 11 | .....d..(...!... |
00B0: 9D 0B D7 5E 79 7F 69 64 38 3B 0D 3B 17 82 60 6F | ...^y.id8;.;..`o |
00C0: 88 8C CB E4 F7 80 3B 8F 3E A7 21 35 6C 14 5F CB | ......;.>.!5l._. |
00D0: 65 25 2D 3D 4B 4B AB F7 ED 3D 19 66 F2 AE 73 2B | e%-=KK...=.f..s+ |
00E0: 5B 12 E5 52 CD 0F 1D 3C 36 65 D6 C0 AA CF DE 6C | [..R...<6e.....l |
00F0: 2F 2D A4 5E 52 B5 C8 12 56 16 32 76 00 05 8E 8E | /-.^R...V.2v.... |
0100: DA B4 05 00 06 8D E2 C5 0B 00 07 C7 91 BE A4 05 | ................ |
0110: 03 01 74 68 65 6D 61 67 69 63 66 6F 72 79 6F 75 | ..themagicforyou |
0120: 00 00 0A AE C1 C8 87 04 06 1B 00 00 0B 01 04 04 | ................ |
0130: 84 02 00 00 00 01 1F 59 61 FA E0 2B 17 FE F8 30 | .......Ya..+...0 |
0140: 28 BF B0 92 3B 55 B8 5D 70 46 FC E9 D4 D7 B1 68 | (...;U.]pF.....h |
0150: 12 D2 26 9E E3 E4 D6 3A 69 9A 0A C9 47 95 9C 16 | ..&....:i...G... |
0160: DB 98 44 F1 F3 1E 3F DB 83 8E F1 29 D7 1F EB 4D | ..D...?....)...M |
0170: 52 F5 C2 07 87 3B 6B F4 7C 75 78 F5 42 AB 47 DC | R....;k.|ux.B.G. |
0180: 19 72 F0 E2 D5 C7 CB 1F E2 4D D8 59 2B 56 12 97 | .r.......M.Y+V.. |
0190: 29 37 4E EB 91 27 C2 AA E2 45 D8 D1 B0 7F 14 94 | )7N..'...E...... |
01A0: 37 EA CA 32 0C 7E 9D 2F 95 F2 9F C3 34 A6 5A D1 | 7..2.~./....4.Z. |
01B0: 64 8B AD 8E 8D D7 AC DB 89 9F 46 A1 7C 08 0B 15 | d.........F.|... |
01C0: B7 F4 20 4C 48 B4 8A B5 B9 2A 43 D1 C2 14 FB 9C | .. LH....*C..... |
01D0: E6 B4 0B FA 2B C0 D7 9B 06 38 FE 95 E3 35 F4 C2 | ....+....8...5.. |
01E0: F0 40 58 B1 C9 CA C8 AF C3 BA 47 AE D2 8A 6D BF | .@X.......G...m. |
01F0: EE A4 95 46 D7 A8 52 E2 9E D6 16 11 39 D1 41 1F | ...F..R.....9.A. |
0200: 03 D6 57 8A B3 F8 34 6D B9 BA 83 51 B4 15 9E E2 | ..W...4m...Q.... |
0210: 5A 35 40 A0 9D 0A C7 48 83 43 DA 2C 85 0E 39 AF | Z5@....H.C.,..9. |
0220: 27 81 74 05 E3 BA 73 24 F3 14 84 A0 5B 60 81 90 | '.t...s$....[`.. |
0230: 64 B1 8C 31 AE 19 00 06 01 00 07 AE C1 C8 87 04 | d..1............ |
0240: 00 09 8D E2 C5 0B                               | ......           |

}
}
===
===
{
00-01: 24 00 00 00
03-02: "#notnowagainplease/$themagicforyou;8c497ce72cbd1e4e"
00-1B: 0A 00 00 00
03-12: "notnowagainplease themagicforyou"
03-1E: ""
05-19: {
05-00: {
00-00: 0B 00 00 00
00-01: 01 00 00 00
00-02: 81 26 96 01
04-03: 178 bytes
0000: 2E BB 9C 3A E6 7E 6B E0 22 AE BC 95 4A EB B4 90 | ...:.~k."...J... |
0010: C0 CB AE 3E BD 81 20 13 A2 2E C3 F5 40 6F 16 1B | ...>.. .....@o.. |
0020: D6 64 E5 08 F1 E0 B7 AF 0C 64 BB DD 28 D8 E6 07 | .d.......d..(... |
0030: 21 11 C1 11 9D 0B D7 5E 79 7F 69 64 38 3B 0D 3B | !......^y.id8;.; |
0040: 17 82 60 6F 88 8C CB E4 F7 80 3B 8F 3E A7 21 35 | ..`o......;.>.!5 |
0050: 6C 14 5F CB 65 25 2D 3D 4B 4B AB F7 ED 3D 19 66 | l._.e%-=KK...=.f |
0060: F2 AE 73 2B 5B 12 E5 52 CD 0F 1D 3C 36 65 D6 C0 | ..s+[..R...<6e.. |
0070: AA CF DE 6C 2F 2D A4 5E 52 B5 C8 12 56 16 32 76 | ...l/-.^R...V.2v |
0080: 00 05 8E 8E DA B4 05 00 06 8D E2 C5 0B 00 07 C7 | ................ |
0090: 91 BE A4 05 03 01 74 68 65 6D 61 67 69 63 66 6F | ......themagicfo |
00A0: 72 79 6F 75 00 00 0A AE C1 C8 87 04 06 1B 00 00 | ryou............ |
00B0: 0B 01                                           | ..               |

04-04: 260 bytes
0000: 00 00 00 01 1F 59 61 FA E0 2B 17 FE F8 30 28 BF | .....Ya..+...0(. |
0010: B0 92 3B 55 B8 5D 70 46 FC E9 D4 D7 B1 68 12 D2 | ..;U.]pF.....h.. |
0020: 26 9E E3 E4 D6 3A 69 9A 0A C9 47 95 9C 16 DB 98 | &....:i...G..... |
0030: 44 F1 F3 1E 3F DB 83 8E F1 29 D7 1F EB 4D 52 F5 | D...?....)...MR. |
0040: C2 07 87 3B 6B F4 7C 75 78 F5 42 AB 47 DC 19 72 | ...;k.|ux.B.G..r |
0050: F0 E2 D5 C7 CB 1F E2 4D D8 59 2B 56 12 97 29 37 | .......M.Y+V..)7 |
0060: 4E EB 91 27 C2 AA E2 45 D8 D1 B0 7F 14 94 37 EA | N..'...E......7. |
0070: CA 32 0C 7E 9D 2F 95 F2 9F C3 34 A6 5A D1 64 8B | .2.~./....4.Z.d. |
0080: AD 8E 8D D7 AC DB 89 9F 46 A1 7C 08 0B 15 B7 F4 | ........F.|..... |
0090: 20 4C 48 B4 8A B5 B9 2A 43 D1 C2 14 FB 9C E6 B4 |  LH....*C....... |
00A0: 0B FA 2B C0 D7 9B 06 38 FE 95 E3 35 F4 C2 F0 40 | ..+....8...5...@ |
00B0: 58 B1 C9 CA C8 AF C3 BA 47 AE D2 8A 6D BF EE A4 | X.......G...m... |
00C0: 95 46 D7 A8 52 E2 9E D6 16 11 39 D1 41 1F 03 D6 | .F..R.....9.A... |
00D0: 57 8A B3 F8 34 6D B9 BA 83 51 B4 15 9E E2 5A 35 | W...4m...Q....Z5 |
00E0: 40 A0 9D 0A C7 48 83 43 DA 2C 85 0E 39 AF 27 81 | @....H.C.,..9.'. |
00F0: 74 05 E3 BA 73 24 F3 14 84 A0 5B 60 81 90 64 B1 | t...s$....[`..d. |
0100: 8C 31 AE 19                                     | .1..             |

}
00-06: 01 00 00 00
00-07: AE 20 F2 40
00-09: 0D 71 71 01
}
}
===

===
signed text...
===

*/
