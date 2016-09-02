/*  
*
* Restore previous chat session
*
*/

#include <stdio.h>
#include <stdlib.h>

#include <fcntl.h>
#include <io.h>

// for rc4
//#include "Expand_IV.h"

#include "skype/skype_rc4.h"

// for aes
#include "crypto/rijndael.h"

// for 41 
#include "decode41.h"

//#include "defs.h"


// rc4 obfuscation

//extern void Skype_RC4_Expand_IV (RC4_context * const rc4, const u32 iv, const u32 flags);
//extern void RC4_crypt (u8 * buffer, u32 bytes, RC4_context * const rc4, const u32 test);


extern int Calculate_CRC32_For41(char *a2, int a3);
extern unsigned int Calculate_CRC32(char *crc32, int bytes);

// socket comm
extern int udp_talk(char *remoteip, unsigned short remoteport, char *buf, int len, char *result);
extern int tcp_talk(char *remoteip, unsigned short remoteport, char *buf, int len, char *result,int need_close);
extern int tcp_talk_recv(char *remoteip, unsigned short remoteport, char *result, int need_close);
extern int tcp_talk_send(char *buf, int len);


// sha1 and rsa crypto function
extern int _get_sha1_data(char *buf, int len, char *outbuf, int need_convert);
extern int _get_sign_data(char *buf, int len, char *outbuf);
//extern int _get_unsign_cred(char *buf, int len, char *outbuf);

// utils
extern int get_blkseq(char *data, int datalen);
extern int show_memory(char *mem, int len, char *text);
extern int get_packet_size(char *data,int len);
extern int decode41(char *data, int len, char *text);
extern int set_packet_size(char *a1, int c);
extern int process_aes(char *buf, int buf_len, int usekey, int blkseq, int need_xor);
extern int first_bytes_correction(char *header, int header_len, char *buf, int buf_len);

//blobs encode 
int encode41_sesspkt_ack(char *buf, int buf_limit_len, uint cmd);

extern int encode41_sess1pkt1(char *buf, int buf_limit_len);
extern int encode41_sess1pkt2(char *buf, int buf_limit_len);
extern int encode41_sess1pkt3(char *buf, int buf_limit_len);
extern int encode41_sess1pkt4(char *buf, int buf_limit_len);
extern int encode41_sess1pkt5(char *buf, int buf_limit_len);
extern int encode41_sess1pkt6(char *buf, int buf_limit_len);
extern int encode41_sess1pkt7(char *buf, int buf_limit_len);
extern int encode41_sess1pkt8(char *buf, int buf_limit_len);

extern int encode41_sess1pkt_cmd24(char *buf, int buf_limit_len);
extern int encode41_sess1pkt_cmd2A(char *buf, int buf_limit_len);
extern int encode41_sess1pkt_cmd13(char *buf, int buf_limit_len);

extern int encode41_newblk1(char *buf, int buf_limit_len);
extern int encode41_newblk2(char *buf, int buf_limit_len);
extern int encode41_newblk3(char *buf, int buf_limit_len);

extern int save_msgcount(int msgcount);
extern int load_msgcount_from_file(int *msgcount);


// global data

extern RC4_context rc4_send;
extern RC4_context rc4_recv;

extern u8 challenge_response[0x80];

extern u8 aes_key[0x20];
extern u32 remote_session_id;
extern u32 LOCAL_SESSION_ID;

extern u32 confirm[0x100];
extern u32 confirm_count;


extern u8 MSG_TEXT[0x100];
extern u8 CHAT_STRING[0x100];
extern u8 CHAT_PEERS[0x100];
extern u8 CREDENTIALS[0x105];
extern uint CREDENTIALS_LEN;
extern u8 NEWBLK[0x1000];
extern uint NEWBLK_LEN;
extern u8 REMOTE_NAME[0x100];

extern u8 REMOTE_CHAT_STRING[0x100];


extern uint NEWSESSION_FLAG;
extern uint NO_HEADERS_FLAG;

extern uint DEBUG_RC4;

extern uint global_chatsync_stage;
extern uint global_chatsync_streamid;


extern u8 RECV_CHAT_COMMANDS[0x100];
extern uint RECV_CHAT_COMMANDS_LEN;

// global aes blkseq key
extern int blkseq;

extern u8 CHAT_PEERS_REVERSED[0x100];


extern uint HEADER_ID_LOCAL_FIRST;
extern uint HEADER_ID_LOCAL_LAST;

extern uint HEADER_ID_REMOTE_FIRST;
extern uint HEADER_ID_REMOTE_LAST;

extern uint HEADER_SLOT_CRC1;
extern uint HEADER_SLOT_CRC2;
extern uint HEADER_SLOT_CRC3;


extern uint HEADER_ID_CMD27_ID;
extern uint HEADER_ID_CMD27_CRC;

extern uint HEADER_ID_SEND;
extern uint HEADER_ID_SEND_CRC;

extern uint START_HEADER_ID;

extern uint pkt_7D_BLOB_00_01;
extern uint pkt_7D_BLOB_00_19;
extern uint pkt_7A_BLOB_00_13;


extern int newchatinit_flag;
extern int restorechat_flag;


unsigned int chatrecv_restorechat_pkts() {
	unsigned int cmd;
	unsigned int tmp;
	u8 buf[0x1000];
	int buf_len;
	int ret;

    restorechat_flag = 1;

	// Files from: "c:\\video\\parse_proto3\\"
	// PROTO3 from 16.11.2015

	debuglog("\n\nStarting chatrecv_restorechat_pkts()\n\n\n");

	// some init variables

	ret = load_localheaders_from_file(&HEADER_ID_LOCAL_FIRST, &tmp);
	if (ret == -1) {
		debuglog("Loading LASTSYNC data failed.\n");
		return -1;
	};
    HEADER_ID_LOCAL_FIRST = HEADER_ID_LOCAL_FIRST + 1;
    HEADER_ID_LOCAL_LAST = HEADER_ID_LOCAL_FIRST;

	ret = load_lastsync_from_file(&HEADER_ID_CMD27_ID, &HEADER_ID_CMD27_CRC);
	if (ret == -1) {
		debuglog("Loading LASTSYNC data failed.\n");
		return -1;
	};
    HEADER_ID_REMOTE_FIRST = HEADER_ID_CMD27_ID;
    HEADER_ID_REMOTE_LAST = HEADER_ID_REMOTE_FIRST;

	global_chatsync_streamid = 0x343EA702;

	// end of init variables

	// PARAM send06

    pkt_7D_BLOB_00_01 = 0x02;
    pkt_7D_BLOB_00_19 = 0x15;

	memset(buf,0,sizeof(buf));
  	buf_len=encode41_sess1pkt_7D(buf, sizeof(buf));
    do_proto_log(buf, buf_len, "send06");
    make_tcp_client_cmdpkt_wrap(buf, buf_len, "sess1pkt_7D");

	// PARAM send07

	pkt_7A_BLOB_00_13 = 0x8CBC998D;

	memset(buf,0,sizeof(buf));
  	buf_len=encode41_sess1pkt_7A(buf, sizeof(buf));
    do_proto_log(buf, buf_len, "send07");
    make_tcp_client_cmdpkt_wrap(buf, buf_len, "sess1pkt_7A");

	// PARAM recv07

	debuglog("Waiting for CHAT_STRING REQ cmd (0x0D)\n");
    cmd = 0x0D;
	while ( check_commands_array(cmd)==0 ){
		ret = make_tcp_client_sess1_recv_loop();
        if (ret < 0) { return -1; };
		show_memory(RECV_CHAT_COMMANDS, RECV_CHAT_COMMANDS_LEN, "RECV_CHAT_COMMANDS:");
	};
	debuglog("Got CHAT_STRING REQ OK cmd\n");
    
    // if returning here, no messages?


    // PARAM send11
    
	debuglog("Entering stage0...\n");
	global_chatsync_stage = 0;

	memset(buf,0,sizeof(buf));
  	buf_len=encode41_sess1pkt_cmd0F_chatok(buf, sizeof(buf));
    do_proto_log(buf, buf_len, "send11");
    make_tcp_client_cmdpkt_wrap(buf, buf_len, "cmd0F_chatok");

	// PARAM send12

	debuglog("Entering stage1...\n");
	global_chatsync_stage = 1;

	HEADER_ID_SEND = HEADER_ID_REMOTE_FIRST;

	memset(buf,0,sizeof(buf));
    buf_len=encode41_sess1pkt_cmd10r_pos2(buf, sizeof(buf));
    do_proto_log(buf, buf_len, "send12");
    make_tcp_client_cmdpkt_wrap(buf, buf_len, "_cmd10r_pos2");

	// PARAM recv13

	debuglog("Waiting for SENDEND cmd (0x13)\n");
    cmd = 0x13;
	while ( check_commands_array(cmd)==0 ){
		ret = make_tcp_client_sess1_recv_loop();
        if (ret < 0) { return -1; };
		show_memory(RECV_CHAT_COMMANDS, RECV_CHAT_COMMANDS_LEN, "RECV_CHAT_COMMANDS:");
	};
	debuglog("Got SENDEND OK cmd\n");

	// PARAM send15

	debuglog("Entering stage2...\n");
	global_chatsync_stage = 2;

    HEADER_ID_SEND = HEADER_ID_REMOTE_LAST;

	debuglog("HEADER_ID_LOCAL_FIRST: 0x%08X\n", HEADER_ID_LOCAL_FIRST);
	debuglog("HEADER_ID_LOCAL_LAST: 0x%08X\n", HEADER_ID_LOCAL_LAST);
    debuglog("HEADER_ID_REMOTE_FIRST = %08X\n", HEADER_ID_REMOTE_FIRST);
    debuglog("HEADER_ID_REMOTE_LAST = %08X\n", HEADER_ID_REMOTE_LAST);

	memset(buf,0,sizeof(buf));
    buf_len=encode41_sess1pkt_cmd15r_reqmsgbody(buf, sizeof(buf));
    do_proto_log(buf, buf_len, "send15");
    make_tcp_client_cmdpkt_wrap(buf, buf_len, "_cmd15r_reqmsgbody");

	// PARAM send16

	global_chatsync_stage = 1;
	make_tcp_client_sess1_send_req();

	// PARAM recv17
	// msg body

	debuglog("Waiting for REMOTE MSG cmd (0x2B)\n");
    cmd = 0x2B;
	while ( check_commands_array(cmd)==0 ){
		ret = make_tcp_client_sess1_recv_loop();
        if (ret < 0) { return -1; };
		show_memory(RECV_CHAT_COMMANDS, RECV_CHAT_COMMANDS_LEN, "RECV_CHAT_COMMANDS:");
	};
	debuglog("Got REMOTE MSG OK cmd\n");

	// PARAM send19

	global_chatsync_stage = 2;
	make_tcp_client_sess1_send_req();

	// PARAM send21

	debuglog("Entering stage3...\n");
	global_chatsync_stage = 3;

    HEADER_ID_SEND = HEADER_ID_REMOTE_LAST;

	memset(buf,0,sizeof(buf));
    buf_len=encode41_sess1pkt_cmd10r_pos1(buf, sizeof(buf));
    do_proto_log(buf, buf_len, "send21");
    make_tcp_client_cmdpkt_wrap(buf, buf_len, "_cmd10r_pos1");

	// PARAM recv21

	debuglog("Waiting for SENDEND cmd (0x13)\n");
    cmd = 0x13;
	while ( check_commands_array(cmd)==0 ){
		ret = make_tcp_client_sess1_recv_loop();
        if (ret < 0) { return -1; };
		show_memory(RECV_CHAT_COMMANDS, RECV_CHAT_COMMANDS_LEN, "RECV_CHAT_COMMANDS:");
	};
	debuglog("Got SENDEND OK cmd\n");

	// PARAM send23

	global_chatsync_stage = 3;
	make_tcp_client_sess1_send_req();

	// PARAM recv22

	debuglog("Waiting for LAST MY HEADER cmd (0x10)\n");
    cmd = 0x10;
	while ( check_commands_array(cmd)==0 ){
		ret = make_tcp_client_sess1_recv_loop();
        if (ret < 0) { return -1; };
		show_memory(RECV_CHAT_COMMANDS, RECV_CHAT_COMMANDS_LEN, "RECV_CHAT_COMMANDS:");
	};
	debuglog("Got LAST MY HEADER OK cmd\n");

	// PARAM send25

	debuglog("Entering stage4...\n");
	global_chatsync_stage = 4;

    // cmd 13 with 1 slots (and 1 local headers in sequence)
	
	debuglog("HEADER_SLOT_CRC1: 0x%08X\n", HEADER_SLOT_CRC1);
	debuglog("HEADER_SLOT_CRC2: 0x%08X\n", HEADER_SLOT_CRC2);

	debuglog("HEADER_ID_LOCAL_FIRST: 0x%08X\n", HEADER_ID_LOCAL_FIRST);
	debuglog("HEADER_ID_LOCAL_LAST: 0x%08X\n", HEADER_ID_LOCAL_LAST);

    debuglog("HEADER_ID_REMOTE_FIRST = %08X\n", HEADER_ID_REMOTE_FIRST);
    debuglog("HEADER_ID_REMOTE_LAST = %08X\n", HEADER_ID_REMOTE_LAST);

    if (HEADER_ID_REMOTE_LAST == 0xFFFFFFFF) {
        debuglog("some err\n");
        return -1;
    };

	memset(buf,0,sizeof(buf));
    buf_len=encode41_sess1pkt_cmd13r5_slotfill(buf, sizeof(buf));
    do_proto_log(buf, buf_len, "send25");
    make_tcp_client_cmdpkt_wrap(buf, buf_len, "_cmd13r5_slotfill");

	// PARAM send26

	global_chatsync_stage = 4;
	make_tcp_client_sess1_send_req();

	// PARAM recv26

    // two cmd 10 in row, need clean buffer
    memset(RECV_CHAT_COMMANDS, 0x00, sizeof(RECV_CHAT_COMMANDS));

	debuglog("Waiting for LAST MY HEADER cmd (0x10)\n");
    cmd = 0x10;
	while ( check_commands_array(cmd)==0 ){
		ret = make_tcp_client_sess1_recv_loop();
        if (ret < 0) { return -1; };
		show_memory(RECV_CHAT_COMMANDS, RECV_CHAT_COMMANDS_LEN, "RECV_CHAT_COMMANDS:");
	};
	debuglog("Got LAST MY HEADER OK cmd\n");

	// PARAM send30

	debuglog("Entering stage5...\n");
	global_chatsync_stage = 5;

	memset(buf,0,sizeof(buf));
    buf_len=encode41_sess1pkt_cmd46(buf, sizeof(buf));
    do_proto_log(buf, buf_len, "send30");
    make_tcp_client_cmdpkt_wrap(buf, buf_len, "_cmd46");

	// PARAM send31

	debuglog("Entering stage6...\n");
	global_chatsync_stage = 6;

	//HEADER_ID_CMD27_ID
	//HEADER_ID_CMD27_CRC
	// we get it from lastsync loaded from file

	memset(buf,0,sizeof(buf));
    buf_len=encode41_sess1pkt_cmd27r(buf, sizeof(buf));
    do_proto_log(buf, buf_len, "send31");
    make_tcp_client_cmdpkt_wrap(buf, buf_len, "_cmd27r");

    // PARAM send32

	global_chatsync_stage = 5;
	make_tcp_client_sess1_send_req();

	// PARAM recv33

	debuglog("Waiting for SYNC FINISH (0x27)\n");
    cmd = 0x27;
	while ( check_commands_array(cmd)==0 ){
		ret = make_tcp_client_sess1_recv_loop();
        if (ret < 0) { return -1; };
		show_memory(RECV_CHAT_COMMANDS, RECV_CHAT_COMMANDS_LEN, "RECV_CHAT_COMMANDS:");
	};
	debuglog("Got SYNC FINISH OK cmd\n");

    ///////////////// stop here and do some checks? //////

	// PARAM send35

	memset(buf,0,sizeof(buf));
    buf_len=encode41_sess1pkt_error(buf, sizeof(buf));
    do_proto_log(buf, buf_len, "send35");
    make_tcp_client_cmdpkt_wrap(buf, buf_len, "_error and close");

	// PARAM recv34
	// 00-08:01
	// 00-03:06 
	// (stage 6 close)

    make_tcp_client_sess1_recv_loop();

	//make_tcp_client_sess1_recv_loop();
    //make_tcp_client_sess1_recv_loop();

    //save_good_remote_chatstring();
    //save last sync?

	save_good_lastsync(HEADER_ID_CMD27_ID, HEADER_ID_CMD27_CRC);
    save_good_localheaders(HEADER_ID_LOCAL_LAST, 0x00000000);

    //msgcount = msgcount + 1;
    //save_msgcount(msgcount);

    // close_connection();

    /*
	debuglog("Waiting for ... (infinite)\n");
	while (1){
		ret = make_tcp_client_sess1_recv_loop();
        if (ret < 0) { return -1; };
	};
    */

    return 1;
};

