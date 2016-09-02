//
// session 1 pkt req msg body
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

extern uint HEADER_ID_REMOTE_FIRST;
extern uint HEADER_ID_REMOTE_LAST;
extern uint HEADER_ID_SEND;

extern uint GOT_REMOTE_MSG_COUNT;

extern int newchatinit_flag;
extern int restorechat_flag;


//
// cmd 15 -- header confirm pkt, req for msgbody
//
//
int encode41_sess1pkt_cmd15r_recurs2(char *buf, int buf_limit_len){
	struct blob_s blob;
	int buf_len;
	int blob_count;
    unsigned int i;
    unsigned int start_i;

	memset(buf,0,sizeof(buf));
    buf_len=0;

	blob_count = 2;

    if (GOT_REMOTE_MSG_COUNT > 0) {
    	blob_count = blob_count + GOT_REMOTE_MSG_COUNT - 1;
    };

    buf_len=make_41cmdencode_recurs(buf, buf_len, blob_count, 0);

    // cmd blob1
    blob.obj_type = 0;
	blob.obj_index = 1;
    blob.obj_data = 0x15;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    debuglog("newchatinit_flag = %d\n", newchatinit_flag);
    debuglog("GOT_REMOTE_MSG_COUNT = %d\n", GOT_REMOTE_MSG_COUNT);

    if (newchatinit_flag == 1) {

        // special case        
        if (HEADER_ID_REMOTE_LAST == HEADER_ID_REMOTE_FIRST) {
            start_i = HEADER_ID_REMOTE_FIRST;
        } else {
            start_i = HEADER_ID_REMOTE_FIRST+1;
        };

    } else {
        start_i = HEADER_ID_REMOTE_FIRST;
    };

    for (i = start_i; i<=HEADER_ID_REMOTE_LAST; i++) {

        blob.obj_type = 0;
    	blob.obj_index = 0x0A;
        blob.obj_data = i;
    	blob.data_ptr = 0;
    	blob.data_size = 0;
        buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);
    	if ( buf_len > buf_limit_len ){
    		debuglog("buffer limit overrun\n");
    		return -1;
    	};

    };


	return buf_len;
};


int encode41_sess1pkt_cmd15r_recurs(char *buf, int buf_limit_len){
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
	intbuf_len=encode41_sess1pkt_cmd15r_recurs2(intbuf,sizeof(intbuf));
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


int encode41_sess1pkt_cmd15r_reqmsgbody(char *buf, int buf_limit_len){
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
	intbuf_len=encode41_sess1pkt_cmd15r_recurs(intbuf,sizeof(intbuf));
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

// header confirm for msgbody send (reply on cmd13 pkt)

// PARAM recv0024
// http://wiki.epycslib.ru/index.php/Newdump5_three_msg_from_scratch

20:32:12.362 T#1348 Logger AES dump from 00915C16 len 36
20:32:12.362 T#1348 Before: 
20:32:12.362 T#1348 38 53 49 FF BC F0 3E 91 E8 CB F1 2B 78 9A AA 22 
20:32:12.362 T#1348 AF 60 C1 DE 4E 86 8C 82 64 EE 44 33 12 E9 94 54 
20:32:12.362 T#1348 F8 43 18 84 D2 00 36 9B 46 7E C4 53 E7 95 3E E3 
20:32:12.362 T#1348 14 88 E1 75 EE 57 
20:32:12.362 T#1348 After: 
20:32:12.362 T#1348 00 A6 01 41 05 04 EF DF 03 02 CB 1B 00 00 02 00 
20:32:12.362 T#1348 01 6D 00 02 B1 D8 01 05 03 41 03 00 01 BA D6 BF 
20:32:12.362 T#1348 B2 0B 00 03 04 04 04 0C 41 02 00 01 15 00 0A AA 
20:32:12.362 T#1348 D7 D4 B1 01 7F 11 
===
PARAM recv0024
===
{
04-EFEF: 2 bytes
0000: CB 1B                                           | ..               |

00-00: 02 00 00 00
00-01: 6D 00 00 00
00-02: 31 6C 00 00
05-03: {
00-01: 3A EB 4F B6
00-03: 04 00 00 00
04-04: 12 bytes
0000: 41 02 00 01 15 00 0A AA D7 D4 B1 01             | A...........     |

}
}
===

===
{
00-01: 15 00 00 00
00-0A: AA 2B 35 16
}
===

*/
