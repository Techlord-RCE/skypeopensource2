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

extern uint pkt_cmd2B_BLOB_00_00;


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
    blob.obj_data = pkt_cmd2B_BLOB_00_00;
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

===
PARAM send027
===
{
00-00: 02 00 00 00
00-01: 6D 00 00 00
00-02: A6 D0 00 00
05-03: {
00-01: 1B 75 E1 D3
00-03: 04 00 00 00
04-04: 191 bytes
0000: 41 02 00 01 2B 05 20 41 05 00 0A C8 91 BE A4 05 | A...+. A........ |
0010: 00 00 03 00 01 01 00 02 81 CD D8 0C 04 03 9F 01 | ................ |
0020: 97 95 8F 1B 01 59 71 E8 51 13 37 2E 9D 3D FF C1 | .....Yq.Q.7..=.. |
0030: BF 12 71 49 F1 10 4C F5 E7 EF ED D8 C4 8D 98 95 | ..qI..L......... |
0040: C7 FE 88 02 B6 67 F8 87 2C D2 B7 21 12 3F E8 9E | .....g..,..!.?.. |
0050: 60 6F CA F0 2D B5 B4 FD 00 45 81 DC 52 7E 6F 19 | `o..-....E..R~o. |
0060: D8 37 AB 94 7A B6 78 2A 71 BF C9 BE 4D 78 78 35 | .7..z.x*q...Mxx5 |
0070: 99 51 04 B8 F7 53 03 ED 09 F1 70 89 45 BE 7C 26 | .Q...S....p.E.|& |
0080: A4 3F 10 F2 AA 25 E8 A6 F9 2B 53 A0 8C 84 29 9C | .?...%...+S...). |
0090: EA B6 D2 71 C9 86 0F 5D 87 78 B0 B3 6F AA 1D E7 | ...q...].x..o... |
00A0: 00 05 96 8E DA B4 05 00 06 8D E2 C5 0B 00 07 C8 | ................ |
00B0: 91 BE A4 05 00 44 01 03 02 74 65 73 74 31 00    | .....D...test1.  |

}
}
===
===
{
00-01: 2B 00 00 00
05-20: {
00-0A: C8 88 8F 54
00-00: 03 00 00 00
00-01: 01 00 00 00
00-02: 81 26 96 01
04-03: 159 bytes
0000: 97 95 8F 1B 01 59 71 E8 51 13 37 2E 9D 3D FF C1 | .....Yq.Q.7..=.. |
0010: BF 12 71 49 F1 10 4C F5 E7 EF ED D8 C4 8D 98 95 | ..qI..L......... |
0020: C7 FE 88 02 B6 67 F8 87 2C D2 B7 21 12 3F E8 9E | .....g..,..!.?.. |
0030: 60 6F CA F0 2D B5 B4 FD 00 45 81 DC 52 7E 6F 19 | `o..-....E..R~o. |
0040: D8 37 AB 94 7A B6 78 2A 71 BF C9 BE 4D 78 78 35 | .7..z.x*q...Mxx5 |
0050: 99 51 04 B8 F7 53 03 ED 09 F1 70 89 45 BE 7C 26 | .Q...S....p.E.|& |
0060: A4 3F 10 F2 AA 25 E8 A6 F9 2B 53 A0 8C 84 29 9C | .?...%...+S...). |
0070: EA B6 D2 71 C9 86 0F 5D 87 78 B0 B3 6F AA 1D E7 | ...q...].x..o... |
0080: 00 05 96 8E DA B4 05 00 06 8D E2 C5 0B 00 07 C8 | ................ |
0090: 91 BE A4 05 00 44 01 03 02 74 65 73 74 31 00    | .....D...test1.  |

}
}
===
Unsigning 04-03 signblock 0x80 bytes...
unsign data:
Len: 0x00000080
6A 18 BC 8D 24 61 45 3C 9B 35 BD B7 D8 75 15 F3  ; j   $aE< 5   u  
 75 5D 00 77 30 23 6E 6F 74 6E 6F 77 61 67 61 69  ; u] w0#notnowagai
 6E 70 6C 65 61 73 65 2F 24 74 68 65 6D 61 67 69  ; nplease/$themagi
 63 66 6F 72 79 6F 75 3B 38 63 34 39 37 63 65 37  ; cforyou;8c497ce7
 32 63 62 64 31 65 34 65 41 07 00 00 03 04 03 1B  ; 2cbd1e4eA       
 E0 3E 31 AE 40 3A E0 12 00 75 03 25 C7 E1 08 41  ;  >1 @:   u %   A
 37 DF 19 9C 55 C0 A8 01 4B E1 08 6E 6F 46 7B 22  ; 7   U   K  noF{"
 2D 15 D2 90 0F CE 8D 65 37 54 E4 BD CA CD 69 BC  ; -      e7T    i 
 
===
SIGNED TEXT
===
recovered signed data:
Len: 0x0000008A
6A 18 BC 8D 24 61 45 3C 9B 35 BD B7 D8 75 15 F3  ; j   $aE< 5   u  
 75 5D 00 77 30 23 6E 6F 74 6E 6F 77 61 67 61 69  ; u] w0#notnowagai
 6E 70 6C 65 61 73 65 2F 24 74 68 65 6D 61 67 69  ; nplease/$themagi
 63 66 6F 72 79 6F 75 3B 38 63 34 39 37 63 65 37  ; cforyou;8c497ce7
 32 63 62 64 31 65 34 65 41 07 00 00 03 04 03 1B  ; 2cbd1e4eA       
 E0 3E 31 AE 40 3A E0 12 00 75 03 25 C7 E1 08 41  ;  >1 @:   u %   A
 37 DF 19 9C 55 C0 A8 01 4B E1 08 00 05 96 8E DA  ; 7   U   K       
 B4 05 00 06 8D E2 C5 0B 00 07 C8 91 BE A4 05 00  ;                 
 44 01 03 02 74 65 73 74 31 00 
{
00-00: 03 00 00 00
04-03: 27 bytes
0000: E0 3E 31 AE 40 3A E0 12 00 75 03 25 C7 E1 08 41 | .>1.@:...u.%...A |
0010: 37 DF 19 9C 55 C0 A8 01 4B E1 08                | 7...U...K..      |

00-05: 16 87 96 56
00-06: 0D 71 71 01
00-07: C8 88 8F 54
00-44: 01 00 00 00
03-02: "test1"
}
===

*/

