//
// session cmd13 (send36)
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
extern int get_chatsync_stage();

extern get_header_chain(int index, uint *remote_header_id, uint *local_header_id, uint *header_id_crc);


extern u8 MSG_TEXT[0x100];
extern u8 CHAT_STRING[0x100];
extern u8 CHAT_PEERS[0x100];
extern u8 CREDENTIALS[0x105];
extern uint CREDENTIALS_LEN;
extern u8 NEWBLK[0x1000];
extern uint NEWBLK_LEN;

extern u8 REMOTE_NAME[0x100];
extern u8 LOCAL_NAME[0x100];

extern u8 CHAT_PEERS_REVERSED[0x100];

extern uint HEADER_ID_LOCAL_FIRST;
extern uint HEADER_ID_LOCAL_LAST;

extern uint HEADER_ID_REMOTE_FIRST;
extern uint HEADER_ID_REMOTE_LAST;
extern uint HEADER_SLOT_CRC1;
extern uint HEADER_SLOT_CRC2;
extern uint HEADER_SLOT_CRC3;

extern uint HEADER_ID_SEND;

extern uint GOT_REMOTE_MSG_COUNT;


extern uint BLOB_0_1;
extern uint BLOB_0_7;
extern uint BLOB_0_9;
extern uint BLOB_0_2__1;


//
// sess1pkt_cmd13 (recv0037)
//
int encode41_sess1pkt_cmd13r2_recurs7msgnum(char *buf, int buf_limit_len, int msgcount){
	struct blob_s blob;
	int buf_len;
	int blob_count;

    //msgcount = 4;

    if (GOT_REMOTE_MSG_COUNT > 0) {
    	msgcount = msgcount + GOT_REMOTE_MSG_COUNT - 1;
    };

	memset(buf,0,sizeof(buf));
    buf_len=0;

	blob_count = 1;

    buf_len=make_41cmdencode_recurs(buf, buf_len, blob_count, 0);

    // number of headers (05-14) in this packet -- blob1
    blob.obj_type = 0;
	blob.obj_index = 2;
    //blob.obj_data = 4;
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


int encode41_sess1pkt_cmd13r2_recurs6(char *buf, int buf_limit_len, int last_msgnum) {
	struct blob_s blob;
	int buf_len;
	int blob_count;
	int ret;

    //last_msgnum = 3;

    if (GOT_REMOTE_MSG_COUNT > 0) {
    	last_msgnum = last_msgnum + GOT_REMOTE_MSG_COUNT - 1;
    };

	memset(buf,0,sizeof(buf));
    buf_len=0;

	blob_count = 4;

    buf_len=make_41cmdencode_recurs(buf, buf_len, blob_count, 0);

    // start working with db
    // create msg2 in newchatinit technically message after we got real messages
    // REMOTE_NAME -- author
    // 1 -- is_service
    ret = save_message_to_db(HEADER_ID_LOCAL_FIRST + last_msgnum, HEADER_SLOT_CRC3, HEADER_ID_LOCAL_FIRST + last_msgnum, LOCAL_NAME, REMOTE_NAME, 1);
    if (ret < 0) { return ret; };
    // end of working with db

    // blob1
    blob.obj_type = 0;
	blob.obj_index = 0x09;
	blob.obj_data = HEADER_ID_LOCAL_FIRST + last_msgnum;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // blob2
    blob.obj_type = 0;
	blob.obj_index = 0x0A;
	blob.obj_data = HEADER_ID_LOCAL_FIRST + last_msgnum;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // some unknown (maybe headers block crc) -- blob3
    blob.obj_type = 0;
	blob.obj_index = 0x15;
	blob.obj_data = HEADER_SLOT_CRC3;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // blob4
    blob.obj_type = 0;
	blob.obj_index = 0x2E;
    blob.obj_data = 0x04;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	if ( buf_len > buf_limit_len ){
		debuglog("buffer limit overrun\n");
		return -1;
	};

	return buf_len;
};


int encode41_sess1pkt_cmd13r2_recurs5msgheaders(char *buf, int buf_limit_len, 
                    uint remote_header_id, uint local_header_id, uint header_id_crc){

	struct blob_s blob;
	int buf_len;
	int blob_count;

	memset(buf,0,sizeof(buf));
    buf_len=0;

	blob_count = 3;

    buf_len=make_41cmdencode_recurs(buf, buf_len, blob_count, 0);

    // blob1
    blob.obj_type = 0;
	blob.obj_index = 0x09;
	blob.obj_data = remote_header_id;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // blob2
    blob.obj_type = 0;
	blob.obj_index = 0x0A;
	blob.obj_data = local_header_id;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // some unknown (maybe headers block crc) -- blob3
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


int encode41_sess1pkt_cmd13r2_recurs4(char *buf, int buf_limit_len){
	struct blob_s blob;
	int buf_len;
	int blob_count;

	memset(buf,0,sizeof(buf));
    buf_len=0;

	blob_count = 2;

    buf_len=make_41cmdencode_recurs(buf, buf_len, blob_count, 0);

    // blob1
    blob.obj_type = 0;
	blob.obj_index = 0x0A;
	blob.obj_data = HEADER_ID_LOCAL_FIRST + 1;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // blob2
    blob.obj_type = 0;
	blob.obj_index = 0x2E;
    blob.obj_data = 0x04;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	if ( buf_len > buf_limit_len ){
		debuglog("buffer limit overrun\n");
		return -1;
	};

	return buf_len;
};


int encode41_sess1pkt_cmd13r2_recurs3(char *buf, int buf_limit_len){
	struct blob_s blob;
	int buf_len;
	int blob_count;

	memset(buf,0,sizeof(buf));
    buf_len=0;

	blob_count = 4;

    buf_len=make_41cmdencode_recurs(buf, buf_len, blob_count, 0);

    debuglog("Updating first techincall message:\n");
    // header_id_crc -- for update
    // remote_header_id -- for update
    update_remoteheader_crc_in_db(HEADER_ID_LOCAL_FIRST, HEADER_SLOT_CRC1, HEADER_ID_REMOTE_FIRST);

    // blob1
    blob.obj_type = 0;
	blob.obj_index = 0x09;
	blob.obj_data = HEADER_ID_REMOTE_FIRST;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // blob2
    blob.obj_type = 0;
	blob.obj_index = 0x0A;
	blob.obj_data = HEADER_ID_LOCAL_FIRST;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // some unknown (maybe headers block crc) -- blob3
    blob.obj_type = 0;
	blob.obj_index = 0x15;
	blob.obj_data = HEADER_SLOT_CRC1;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // some flag -- blob4
    blob.obj_type = 0;
	blob.obj_index = 0x2E;
    blob.obj_data = 0x04;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	if ( buf_len > buf_limit_len ){
		debuglog("buffer limit overrun\n");
		return -1;
	};

	return buf_len;
};


//
// main include blobs recursion
// 
int encode41_sess1pkt_cmd13r2_recurs2(char *buf, int buf_limit_len){
	struct blob_s blob;
	int buf_len;
	int blob_count;
    int i;
    int last_msgnum;
    int msgcount;

	char intbuf[0x1000];
	int intbuf_len;

	char intbuf2[0x1000];
	int intbuf2_len;


	memset(buf,0,sizeof(buf));
    buf_len=0;

	blob_count = 8;

    if (HEADER_ID_REMOTE_LAST == HEADER_ID_REMOTE_FIRST) {
    	blob_count = 7;
    };

    if (GOT_REMOTE_MSG_COUNT > 0) {
    	blob_count = blob_count + GOT_REMOTE_MSG_COUNT - 1;
    };

    buf_len=make_41cmdencode_recurs(buf, buf_len, blob_count, 0);

    // cmdid, send headers -- blob1
    blob.obj_type = 0;
	blob.obj_index = 1;
    blob.obj_data = 0x13;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // header_id local (first appear) -- blob2
    blob.obj_type = 0;
	blob.obj_index = 0x0F;
	//blob.obj_data = 0x27AAA1B0;
	blob.obj_data = HEADER_ID_LOCAL_FIRST;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // first msg "notnowagainplease"
    // ALLOC1 recursive -- blob3
	intbuf_len=encode41_sess1pkt_cmd13r2_recurs3(intbuf,sizeof(intbuf));
    blob.obj_type = 5;
	blob.obj_index = 0x14;
    blob.obj_data = 0;
	blob.data_ptr = (int)intbuf;
	blob.data_size = intbuf_len;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // second "short" with just 00-0A and 00-2E: 04 (sync version of remote side?)
    // ALLOC2 recursive -- blob4
	intbuf_len=encode41_sess1pkt_cmd13r2_recurs4(intbuf,sizeof(intbuf));
    blob.obj_type = 5;
	blob.obj_index = 0x14;
    blob.obj_data = 0;
	blob.data_ptr = (int)intbuf;
	blob.data_size = intbuf_len;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);


if (HEADER_ID_REMOTE_LAST == HEADER_ID_REMOTE_FIRST) {
    last_msgnum = 2;
    msgcount = 3;
} else {
    last_msgnum = 3;
    msgcount = 4;

    printf("GOT_REMOTE_MSG_COUNT: %d\n", GOT_REMOTE_MSG_COUNT);

    dump_headers();

    // just for db update with first msg
    for (i = 0; i < GOT_REMOTE_MSG_COUNT; i++) {
        uint remote_header_id;
        uint local_header_id;
        uint header_id_crc;

        remote_header_id = 0;
        local_header_id = 0;
        header_id_crc = 0;

        get_header_chain(i+1, &remote_header_id, &local_header_id, &header_id_crc);

        local_header_id = HEADER_ID_LOCAL_FIRST + 2 + i;

        // local_header_id -- for select
        // header_id_crc -- for update
        // remote_header_id -- for update
        update_localheader_crc_in_db(local_header_id, header_id_crc, remote_header_id);
    };
    // end of db update


    for (i = 0; i<GOT_REMOTE_MSG_COUNT; i++) {
        uint remote_header_id;
        uint local_header_id;
        uint header_id_crc;

        remote_header_id = 0;
        local_header_id = 0;
        header_id_crc = 0;

        get_header_chain(i+1, &remote_header_id, &local_header_id, &header_id_crc);

        local_header_id = HEADER_ID_LOCAL_FIRST + 2 + i;

        // first msg data header
        // ALLOC2 recursive -- blob5
    	intbuf_len=encode41_sess1pkt_cmd13r2_recurs5msgheaders(intbuf,sizeof(intbuf), remote_header_id, local_header_id, header_id_crc);
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

};

    // slot for new msg we want to send
    // ALLOC2 recursive -- blob6
	intbuf_len=encode41_sess1pkt_cmd13r2_recurs6(intbuf,sizeof(intbuf), last_msgnum);
    blob.obj_type = 5;
	blob.obj_index = 0x14;
    blob.obj_data = 0;
	blob.data_ptr = (int)intbuf;
	blob.data_size = intbuf_len;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // chat peers -- blob7
    blob.obj_type = 3;
	blob.obj_index = 0x12;
    blob.obj_data = 0;
	//blob.data_ptr = (int)CHAT_PEERS_REVERSED;
	//blob.data_size = strlen(CHAT_PEERS_REVERSED)+1;
	blob.data_ptr = (int)CHAT_PEERS;
	blob.data_size = strlen(CHAT_PEERS)+1;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	// number of headers chains in this packet -- blob8
	intbuf2_len=encode41_sess1pkt_cmd13r2_recurs7msgnum(intbuf2,sizeof(intbuf2), msgcount);
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


int encode41_sess1pkt_cmd13r2_recurs(char *buf, int buf_limit_len){
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

    // 00-03 stage -- blob2
    blob.obj_type = 0;
	blob.obj_index = 3;
	blob.obj_data = get_chatsync_stage();
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // blob3 ALLOC1 recursive 41
	intbuf_len=encode41_sess1pkt_cmd13r2_recurs2(intbuf,sizeof(intbuf));
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


int encode41_sess1pkt_cmd13r2_slotfill(char *buf, int buf_limit_len){
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
	intbuf_len=encode41_sess1pkt_cmd13r2_recurs(intbuf,sizeof(intbuf));
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

sess1pkt_cmd13

===
PARAM send036
===
{
00-00: 02 00 00 00
00-01: 6D 00 00 00
00-02: 12 99 00 00
05-03: {
00-01: 43 82 D4 50
00-03: 06 00 00 00
04-04: 148 bytes
0000: 41 08 00 01 13 00 0F B0 C3 AA BD 02 05 14 41 04 | A.............A. |
0010: 00 09 D2 D9 E9 A9 05 00 0A B0 C3 AA BD 02 00 15 | ................ |
0020: A8 F3 D8 28 00 2E 04 05 14 41 02 00 0A B1 C3 AA | ...(.....A...... |
0030: BD 02 00 2E 04 05 14 41 03 00 09 D3 D9 E9 A9 05 | .......A........ |
0040: 00 0A B2 C3 AA BD 02 00 15 FA FB A7 B6 0F 05 14 | ................ |
0050: 41 04 00 09 B3 C3 AA BD 02 00 0A B3 C3 AA BD 02 | A............... |
0060: 00 15 E8 E0 E4 F6 06 00 2E 04 03 12 6E 6F 74 6E | ............notn |
0070: 6F 77 61 67 61 69 6E 70 6C 65 61 73 65 20 74 68 | owagainplease th |
0080: 65 6D 61 67 69 63 66 6F 72 79 6F 75 00 05 2F 41 | emagicforyou../A |
0090: 01 00 02 04                                     | ....             |

}
}
===
===
{
00-01: 13 00 00 00
00-0F: B0 A1 AA 27
05-14: {
00-09: D2 6C 3A 55
00-0A: B0 A1 AA 27
00-15: A8 39 16 05
00-2E: 04 00 00 00
}
05-14: {
00-0A: B1 A1 AA 27
00-2E: 04 00 00 00
}
05-14: {
00-09: D3 6C 3A 55
00-0A: B2 A1 AA 27
00-15: FA FD C9 F6
}
05-14: {
00-09: B3 A1 AA 27
00-0A: B3 A1 AA 27
00-15: 68 30 D9 6E
00-2E: 04 00 00 00
}
03-12: "notnowagainplease themagicforyou"
05-2F: {
00-02: 04 00 00 00
}
}
===

*/
