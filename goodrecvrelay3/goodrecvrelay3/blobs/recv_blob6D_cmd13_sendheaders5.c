//
// session 2 pkt
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


extern uint HEADER_ID_LOCAL_FIRST;
extern uint HEADER_ID_LOCAL_LAST;

extern uint HEADER_ID_REMOTE_FIRST;
extern uint HEADER_ID_REMOTE_LAST;

extern uint HEADER_SLOT_CRC1;
extern uint HEADER_SLOT_CRC2;
extern uint HEADER_SLOT_CRC3;

extern uint GOT_REMOTE_MSG_COUNT;

extern uint BLOB_0_1;
extern uint BLOB_0_7;
extern uint BLOB_0_9;
extern uint BLOB_0_2__1;


//
// cmd13 recv one (add new msg header)
//
int encode41_sess1pkt_cmd13r5_recurs4count(char *buf, int buf_limit_len){
	struct blob_s blob;
	uint session_id;
	uint session_cmd;
	int buf_len;
	int blob_count;
    int msgcount;

	session_id=00;
	session_cmd=0xA6;

	memset(buf,0,sizeof(buf));
    buf_len=0;

    msgcount = 1;
    if (GOT_REMOTE_MSG_COUNT > 0) {
    	msgcount = msgcount + GOT_REMOTE_MSG_COUNT - 1;
    };

	blob_count = 1;

    buf_len=make_41cmdencode_recurs(buf, buf_len, blob_count, 0);

    // 00-02 info -- blob1
    blob.obj_type = 0;
	blob.obj_index = 2;
    //blob.obj_data = 1;
    blob.obj_data = msgcount;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	if ( buf_len > buf_limit_len ){
		debuglog("buffer limit overrun\n");
		return -1;
	};

	return buf_len;
};


int encode41_sess1pkt_cmd13r5_recurs3msgheaders(char *buf, int buf_limit_len,
                    uint remote_header_id, uint local_header_id, uint header_id_crc) {

	struct blob_s blob;
	uint session_id;
	uint session_cmd;
	int buf_len;
	int blob_count;

	session_id=00;
	session_cmd=0xA6;

	memset(buf,0,sizeof(buf));
    buf_len=0;

	blob_count = 3;

    buf_len=make_41cmdencode_recurs(buf, buf_len, blob_count, 0);

    // new header_id -- blob1
    blob.obj_type = 0;
	blob.obj_index = 0x09;
	blob.obj_data = remote_header_id;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // new header_id (the same) -- blob2
    blob.obj_type = 0;
	blob.obj_index = 0x0A;
	blob.obj_data = local_header_id;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // header_id_crc -- blob3
    blob.obj_type = 0;
	blob.obj_index = 0x15;
	blob.obj_data = header_id_crc;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	if ( buf_len > buf_limit_len ){
		debuglog("buffer limit overrun\n");
		return -1;
	};

	return buf_len;
};


int encode41_sess1pkt_cmd13r5_recurs2(char *buf, int buf_limit_len){
	struct blob_s blob;
	int buf_len;
	int blob_count;
	int i;

	char intbuf[0x1000];
	int intbuf_len;
	char intbuf2[0x1000];
	int intbuf2_len;

	memset(buf,0,sizeof(buf));
    buf_len=0;

	blob_count = 4;

    if (GOT_REMOTE_MSG_COUNT > 0) {
    	blob_count = blob_count + GOT_REMOTE_MSG_COUNT - 1;
    };

    buf_len=make_41cmdencode_recurs(buf, buf_len, blob_count, 0);

    // sync request -- blob1
    blob.obj_type = 0;
	blob.obj_index = 1;
    blob.obj_data = 0x13;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // header_id remote last -- blob2
    blob.obj_type = 0;
	blob.obj_index = 0x0F;
    //blob.obj_data = HEADER_ID_LOCAL_LAST;
    blob.obj_data = HEADER_ID_LOCAL_FIRST;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);


    for (i = 0; i<GOT_REMOTE_MSG_COUNT; i++) {
        uint remote_header_id;
        uint local_header_id;
        uint header_id_crc;

        get_header_chain(i, &remote_header_id, &local_header_id, &header_id_crc);

        local_header_id = HEADER_ID_LOCAL_FIRST + 1 + i;

        // local_header_id -- for select
        // header_id_crc -- for select
        // remote_header_id -- for update
        update_localheader_crc_in_db(local_header_id, header_id_crc, remote_header_id);

        // blob3 -- ALLOC1 recursive
    	intbuf_len=encode41_sess1pkt_cmd13r5_recurs3msgheaders(intbuf,sizeof(intbuf), remote_header_id, local_header_id, header_id_crc);
        blob.obj_type = 5;
    	blob.obj_index = 0x14;
        blob.obj_data = 0;
    	blob.data_ptr = (int)intbuf;
    	blob.data_size = intbuf_len;
        buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);
    	if ( buf_len > buf_limit_len ){
    		debuglog("buffer limit overrun\n");
            return -1;
        };


    };


	// blob4 -- ALLOC2 recursive
	intbuf2_len=encode41_sess1pkt_cmd13r5_recurs4count(intbuf2,sizeof(intbuf2));
    blob.obj_type = 5;
	blob.obj_index = 0x2F;
    blob.obj_data = 0;
	blob.data_ptr = (int)intbuf2;
	blob.data_size = intbuf2_len;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	if ( buf_len > buf_limit_len ){
		debuglog("buffer limit overrun\n");
		return -1;
	};

	return buf_len;
};


int encode41_sess1pkt_cmd13r5_recurs(char *buf, int buf_limit_len){
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

    // ALLOC1 recursive 41 -- blob3
	intbuf_len=encode41_sess1pkt_cmd13r5_recurs2(intbuf,sizeof(intbuf));
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


int encode41_sess1pkt_cmd13r5_slotfill(char *buf, int buf_limit_len){
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

	// blob4 -- ALLOC1 recursive
	intbuf_len=encode41_sess1pkt_cmd13r5_recurs(intbuf,sizeof(intbuf));
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

PROTO2 (16.11.2015)

===
PARAM send034
===
{
04-EFEF: 3 bytes
0000: B6 A3 36                                        | ..6              |

00-00: 02 00 00 00
00-01: 6D 00 00 00
00-02: 3D E6 00 00
05-03: {
00-01: D5 F2 DD A2
00-03: 06 00 00 00
04-04: 44 bytes
0000: 41 04 00 01 13 00 0F B3 C3 AA BD 02 05 14 41 03 | A.............A. |
0010: 00 09 D5 D9 E9 A9 05 00 0A B4 C3 AA BD 02 00 15 | ................ |
0020: D2 E1 C6 A6 06 05 2F 41 01 00 02 01             | ....../A....     |

}
}
===
===
{
00-01: 13 00 00 00
00-0F: B3 A1 AA 27
05-14: {
00-09: D5 6C 3A 55
00-0A: B4 A1 AA 27
00-15: D2 B0 D1 64
}
05-2F: {
00-02: 01 00 00 00
}
}
===

*/

