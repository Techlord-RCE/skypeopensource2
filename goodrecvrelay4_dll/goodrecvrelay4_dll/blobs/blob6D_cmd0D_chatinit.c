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


extern u8 CREDENTIALS188[0x189];
extern uint CREDENTIALS188_LEN;

extern uint BLOB_0_1;


//
// sess1pkt3 chatinit 6D_cmd0D
//
int encode41_sess1pkt3_recurs2(char *buf, int buf_limit_len){
	struct blob_s blob;
	int buf_len;
	int blob_count;
	//u8 chat_string[]="#xoteg_iam/$xot_iam;4fef7b015cb20ad0";

	memset(buf,0,sizeof(buf));
    buf_len=0;

	blob_count = 4;

    buf_len=make_41cmdencode_recurs(buf, buf_len, blob_count, 0);

    // hz .. blob1
    blob.obj_type = 0;
	blob.obj_index = 1;
    blob.obj_data = 0x0D;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // blob2 ALLOC1 chat name string
    blob.obj_type = 3;
	blob.obj_index = 2;
    blob.obj_data = 0;
	blob.data_ptr = (int)CHAT_STRING;
	blob.data_size = strlen(CHAT_STRING)+1;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // hz .. blob3
    blob.obj_type = 0;
	blob.obj_index = 0x1C;
    blob.obj_data = 0x01;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // hz .. blob4
    blob.obj_type = 0;
	blob.obj_index = 0x1D;
    blob.obj_data = 0x01;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	if ( buf_len > buf_limit_len ){
		debuglog("buffer limit overrun\n");
		return -1;
	};

	return buf_len;
};


int encode41_sess1pkt3_recurs(char *buf, int buf_limit_len){
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

    buf_len=make_41cmdencode_recurs(buf, buf_len, blob_count, 0);

    // 00-01 our chat seq id -- blob1
    blob.obj_type = 0;
	blob.obj_index = 1;
	//blob.obj_data = 0xCF0522DE;
	//blob.obj_data = 0xBF356579;
	blob.obj_data = get_chatsync_streamid();
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // 00-03 stage0 -- blob2
    blob.obj_type = 0;
	blob.obj_index = 3;
	blob.obj_data = get_chatsync_stage();
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // blob3 ALLOC1 recursive 41
	intbuf_len=encode41_sess1pkt3_recurs2(intbuf,sizeof(intbuf));
    blob.obj_type = 0x04;
	blob.obj_index = 0x04;
    blob.obj_data = 0;
	blob.data_ptr = (int)intbuf;
	blob.data_size = intbuf_len;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // hz .. blob4
    blob.obj_type = 0;
	blob.obj_index = 7;
    blob.obj_data = 0x0A;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	if ( buf_len > buf_limit_len ){
		debuglog("buffer limit overrun\n");
		return -1;
	};

	return buf_len;
};


int encode41_sess1pkt_cmd0D(char *buf, int buf_limit_len){
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
    //blob.obj_data = 0x6C6A;
	blob.obj_data = get_cmdid_seqnum();
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	// blob4 -- ALLOC1 recursive 41
	intbuf_len=encode41_sess1pkt3_recurs(intbuf,sizeof(intbuf));
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

sess1pkt3

06:07:54.587 T#5096 Logger AES dump from 00914C97 len 67
06:07:54.587 T#5096 Before: 
06:07:54.587 T#5096 00 A6 01 41 04 00 00 02 00 01 6D 00 02 EA D8 01 
06:07:54.587 T#5096 05 03 41 04 00 01 DE C5 94 F8 0C 00 03 00 04 04 
06:07:54.587 T#5096 41 41 04 00 01 0D 03 02 23 74 68 65 6D 61 67 69 
06:07:54.587 T#5096 63 66 6F 72 79 6F 75 2F 24 6E 6F 74 6E 6F 77 61 
06:07:54.587 T#5096 67 61 69 6E 70 6C 65 61 73 65 3B 34 66 65 61 36 
06:07:54.587 T#5096 36 30 31 33 63 64 64 32 30 32 38 00 00 1C 01 00 
06:07:54.587 T#5096 1D 01 00 07 0A E9 B0 
06:07:54.587 T#5096 After: 
===
PARAM send0005
===
{
00-00: 02 00 00 00
00-01: 6D 00 00 00
00-02: 6A 6C 00 00
05-03: {
00-01: DE 22 05 CF
00-03: 00 00 00 00
04-04: 65 bytes
0000: 41 04 00 01 0D 03 02 23 74 68 65 6D 61 67 69 63 | A......#themagic |
0010: 66 6F 72 79 6F 75 2F 24 6E 6F 74 6E 6F 77 61 67 | foryou/$notnowag |
0020: 61 69 6E 70 6C 65 61 73 65 3B 34 66 65 61 36 36 | ainplease;4fea66 |
0030: 30 31 33 63 64 64 32 30 32 38 00 00 1C 01 00 1D | 013cdd2028...... |
0040: 01                                              | .                |

00-07: 0A 00 00 00
}
}
===
===
{
00-01: 0D 00 00 00
03-02: "#themagicforyou/$notnowagainplease;4fea66013cdd2028"
00-1C: 01 00 00 00
00-1D: 01 00 00 00
}
===

*/

