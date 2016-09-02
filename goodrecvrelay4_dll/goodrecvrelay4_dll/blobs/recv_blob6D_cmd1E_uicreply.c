//
// session 4 pkt
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


//
// (recv0046) uic reply pkt
// cmd 1E
//
int encode41_sess1pkt_cmd1E_recurs2(char *buf, int buf_limit_len){
	struct blob_s blob;
	int buf_len;
	int blob_count;

	memset(buf,0,sizeof(buf));
    buf_len=0;

	blob_count = 3;

    buf_len=make_41cmdencode_recurs(buf, buf_len, blob_count, 0);

    // cmd -- blob1 (uic reply)
    blob.obj_type = 0;
	blob.obj_index = 1;
    blob.obj_data = 0x1E;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	// some flag -- blob2
    blob.obj_type = 0;
	blob.obj_index = 0x0C;
    blob.obj_data = 0x02;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // blob3
    blob.obj_type = 0x04;
	blob.obj_index = 0x0B;
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


int encode41_sess1pkt_cmd1E_recurs(char *buf, int buf_limit_len){
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

    // 00-03 stage -- blob2
    blob.obj_type = 0;
	blob.obj_index = 3;
	blob.obj_data = get_chatsync_stage();
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // blob3 ALLOC1 recursive 41
	intbuf_len=encode41_sess1pkt_cmd1E_recurs2(intbuf,sizeof(intbuf));
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


int encode41_sess1pkt_cmd1E_uicreply(char *buf, int buf_limit_len){
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
	intbuf_len=encode41_sess1pkt_cmd1E_recurs(intbuf,sizeof(intbuf));
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

// just send our certificate (credentials)

// (PARAM recv0046) 

20:32:12.909 T#1348 After: 
20:32:12.909 T#1348 00 A6 01 41 05 04 EF DF 03 02 55 FF 00 00 02 00 
20:32:12.909 T#1348 01 6D 00 02 CB 97 03 05 03 41 03 00 01 BA D6 BF 
20:32:12.909 T#1348 B2 0B 00 03 08 04 04 90 02 41 03 00 01 1E 00 0C 
20:32:12.909 T#1348 02 04 0B 84 02 00 00 00 01 0E 66 7C F5 65 9D C6 
20:32:12.909 T#1348 40 D9 22 15 49 CF 60 F2 26 F8 19 17 79 D9 92 43 
20:32:12.909 T#1348 29 0C 52 78 6C B3 9D 1A E7 5F 42 4F B1 85 B4 29 
20:32:12.909 T#1348 A7 62 B7 41 8F 7A 7F 7B B7 1B A5 A8 74 36 41 A4 
20:32:12.909 T#1348 C8 E5 D1 4E D0 16 D0 F3 BB FF E6 B6 0A 55 63 45 
20:32:12.909 T#1348 95 97 86 D9 F9 F4 04 3F 3D E7 5F 62 1E 37 C0 50 
20:32:12.909 T#1348 2B 9E F6 8B 20 E6 CB 46 AE 3A AE 66 11 12 E7 3C 
20:32:12.909 T#1348 1B 22 25 B3 D6 17 46 77 2E 29 2D 45 89 29 65 98 
20:32:12.909 T#1348 E9 AF DC C2 66 25 FC D5 3B 93 0D 5E A0 A3 82 6F 
20:32:12.909 T#1348 18 1D F5 7D D7 BC 2E 72 D9 06 9E A0 D7 75 6E DE 
20:32:12.909 T#1348 55 31 A3 35 2E D8 C8 C8 5A 1D FB E5 63 30 A1 85 
20:32:12.909 T#1348 A7 F5 41 72 7D CD 17 47 F2 48 86 3F AA E1 AA 29 
20:32:12.909 T#1348 31 6C 04 55 C3 19 8B 8A BB BE 12 63 6F BB 3D EF 
20:32:12.909 T#1348 8E A8 0A F9 90 C4 CD A7 64 F0 0D A1 07 D3 AF 68 
20:32:12.909 T#1348 2F C7 4E CF 49 E0 97 04 B1 E6 F5 51 AE E8 C5 0E 
20:32:12.909 T#1348 64 DB DF 9E A8 BF A3 D6 76 65 7B 3F DA E8 81 3A 
20:32:12.909 T#1348 5B 94 7F 77 96 46 64 B4 32 B2 DA 
===
PARAM recv0046
===
{
04-EFEF: 2 bytes
0000: 55 FF                                           | U.               |

00-00: 02 00 00 00
00-01: 6D 00 00 00
00-02: CB CB 00 00
05-03: {
00-01: 3A EB 4F B6
00-03: 08 00 00 00
04-04: 272 bytes
0000: 41 03 00 01 1E 00 0C 02 04 0B 84 02 00 00 00 01 | A............... |
0010: 0E 66 7C F5 65 9D C6 40 D9 22 15 49 CF 60 F2 26 | .f|.e..@.".I.`.& |
0020: F8 19 17 79 D9 92 43 29 0C 52 78 6C B3 9D 1A E7 | ...y..C).Rxl.... |
0030: 5F 42 4F B1 85 B4 29 A7 62 B7 41 8F 7A 7F 7B B7 | _BO...).b.A.z.{. |
0040: 1B A5 A8 74 36 41 A4 C8 E5 D1 4E D0 16 D0 F3 BB | ...t6A....N..... |
0050: FF E6 B6 0A 55 63 45 95 97 86 D9 F9 F4 04 3F 3D | ....UcE.......?= |
0060: E7 5F 62 1E 37 C0 50 2B 9E F6 8B 20 E6 CB 46 AE | ._b.7.P+... ..F. |
0070: 3A AE 66 11 12 E7 3C 1B 22 25 B3 D6 17 46 77 2E | :.f...<."%...Fw. |
0080: 29 2D 45 89 29 65 98 E9 AF DC C2 66 25 FC D5 3B | )-E.)e.....f%..; |
0090: 93 0D 5E A0 A3 82 6F 18 1D F5 7D D7 BC 2E 72 D9 | ..^...o...}...r. |
00A0: 06 9E A0 D7 75 6E DE 55 31 A3 35 2E D8 C8 C8 5A | ....un.U1.5....Z |
00B0: 1D FB E5 63 30 A1 85 A7 F5 41 72 7D CD 17 47 F2 | ...c0....Ar}..G. |
00C0: 48 86 3F AA E1 AA 29 31 6C 04 55 C3 19 8B 8A BB | H.?...)1l.U..... |
00D0: BE 12 63 6F BB 3D EF 8E A8 0A F9 90 C4 CD A7 64 | ..co.=.........d |
00E0: F0 0D A1 07 D3 AF 68 2F C7 4E CF 49 E0 97 04 B1 | ......h/.N.I.... |
00F0: E6 F5 51 AE E8 C5 0E 64 DB DF 9E A8 BF A3 D6 76 | ..Q....d.......v |
0100: 65 7B 3F DA E8 81 3A 5B 94 7F 77 96 46 64 B4 32 | e{?...:[..w.Fd.2 |

}
}
===

===
{
00-01: 1E 00 00 00
00-0C: 02 00 00 00
04-0B: 260 bytes
0000: 00 00 00 01 0E 66 7C F5 65 9D C6 40 D9 22 15 49 | .....f|.e..@.".I |
0010: CF 60 F2 26 F8 19 17 79 D9 92 43 29 0C 52 78 6C | .`.&...y..C).Rxl |
0020: B3 9D 1A E7 5F 42 4F B1 85 B4 29 A7 62 B7 41 8F | ...._BO...).b.A. |
0030: 7A 7F 7B B7 1B A5 A8 74 36 41 A4 C8 E5 D1 4E D0 | z.{....t6A....N. |
0040: 16 D0 F3 BB FF E6 B6 0A 55 63 45 95 97 86 D9 F9 | ........UcE..... |
0050: F4 04 3F 3D E7 5F 62 1E 37 C0 50 2B 9E F6 8B 20 | ..?=._b.7.P+...  |
0060: E6 CB 46 AE 3A AE 66 11 12 E7 3C 1B 22 25 B3 D6 | ..F.:.f...<."%.. |
0070: 17 46 77 2E 29 2D 45 89 29 65 98 E9 AF DC C2 66 | .Fw.)-E.)e.....f |
0080: 25 FC D5 3B 93 0D 5E A0 A3 82 6F 18 1D F5 7D D7 | %..;..^...o...}. |
0090: BC 2E 72 D9 06 9E A0 D7 75 6E DE 55 31 A3 35 2E | ..r.....un.U1.5. |
00A0: D8 C8 C8 5A 1D FB E5 63 30 A1 85 A7 F5 41 72 7D | ...Z...c0....Ar} |
00B0: CD 17 47 F2 48 86 3F AA E1 AA 29 31 6C 04 55 C3 | ..G.H.?...)1l.U. |
00C0: 19 8B 8A BB BE 12 63 6F BB 3D EF 8E A8 0A F9 90 | ......co.=...... |
00D0: C4 CD A7 64 F0 0D A1 07 D3 AF 68 2F C7 4E CF 49 | ...d......h/.N.I |
00E0: E0 97 04 B1 E6 F5 51 AE E8 C5 0E 64 DB DF 9E A8 | ......Q....d.... |
00F0: BF A3 D6 76 65 7B 3F DA E8 81 3A 5B 94 7F 77 96 | ...ve{?...:[..w. |
0100: 46 64 B4 32                                     | Fd.2             |

}
===

*/

