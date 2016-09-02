/*  
*
* Init new chat session
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

extern int do_proto_log(u8 *pktbuf, u32 pktlen, char *header);

// global data

extern RC4_context rc4_send;
extern RC4_context rc4_recv;

extern u8 challenge_response[0x80];

extern u8 aes_key[0x20];
extern u32 remote_session_id;
extern u32 LOCAL_SESSION_ID;

extern u32 confirm[0x100];
extern u32 confirm_count;


extern u8 REMOTE_NAME[0x100];
extern u8 LOCAL_NAME[0x100];
extern u8 MSG_TEXT[0x100];

extern u8 CHAT_STRING[0x100];
extern u8 CHAT_PEERS[0x100];
extern u8 CREDENTIALS[0x105];
extern uint CREDENTIALS_LEN;
extern u8 NEWBLK[0x1000];
extern uint NEWBLK_LEN;


extern u8 REMOTE_CHAT_STRING[0x100];

extern uint HEADER_ID_LOCAL_FIRST;
extern uint HEADER_ID_LOCAL_LAST;

extern uint HEADER_ID_REMOTE_FIRST;
extern uint HEADER_ID_REMOTE_LAST;
extern uint HEADER_SLOT_CRC1;
extern uint HEADER_SLOT_CRC2;
extern uint HEADER_SLOT_CRC3;

extern uint GOT_REMOTE_MSG_COUNT;

extern uint HEADER_ID_CMD27_CRC;
extern uint HEADER_ID_CMD27_ID;

extern uint HEADER_ID_SEND;
extern uint HEADER_ID_SEND_CRC;

extern uint START_HEADER_ID;

extern uint global_chatsync_streamid;

extern uint pkt_7D_BLOB_00_01;
extern uint pkt_7D_BLOB_00_19;
extern uint pkt_7A_BLOB_00_13;


extern uint NEWSESSION_FLAG;
extern uint NO_HEADERS_FLAG;

extern uint DEBUG_RC4;

extern uint global_chatsync_stage;

extern u8 RECV_CHAT_COMMANDS[0x100];
extern uint RECV_CHAT_COMMANDS_LEN;

// global aes blkseq key
extern int blkseq;

extern u8 CHAT_PEERS_REVERSED[0x100];

extern int newchatinit_flag;
extern int restorechat_flag;



unsigned int chatrecv_newchatinit_pkts() {
	unsigned int cmd;
	u8 buf[0x1000];
	int buf_len;
	int ret;
    uint msg_count_tmp;
    FILE *fp;

    debuglog("Do chatrecv_newchatinit_pkts() recv...\n");   

    newchatinit_flag = 1;

    // init

    pkt_7D_BLOB_00_01 = 02;
    pkt_7D_BLOB_00_19 = 0x13;

	pkt_7A_BLOB_00_13 = 0x8CBC998D;

    //HEADER_ID_LOCAL_FIRST = 0x27AAA1B0;
    HEADER_ID_LOCAL_FIRST = 0x29AAA1B0;

    // end of init



    //make_tcp_client_prepare_newblk_msg();
    //HEADER_SLOT_CRC1 = get_header_id_crc_cmd24();
    //debuglog("HEADER_SLOT_CRC1 = 0x%08X\n", HEADER_SLOT_CRC1);



	// Files from: "c:\\video\\parse_proto1\\"
	// PROTO1 from 16.11.2015

	debuglog("Entering stage0...\n");
	global_chatsync_stage = 0;

	// PARAM send05

	memset(buf,0,sizeof(buf));
  	buf_len=encode41_sess1pkt_7D(buf, sizeof(buf));
    do_proto_log(buf, buf_len, "send05");
    make_tcp_client_cmdpkt_wrap(buf, buf_len, "sess1pkt_7D");

	// PARAM send06

	memset(buf,0,sizeof(buf));
  	buf_len=encode41_sess1pkt_7A(buf, sizeof(buf));
    do_proto_log(buf, buf_len, "send06");
    make_tcp_client_cmdpkt_wrap(buf, buf_len, "sess1pkt_7A");

	// PARAM recv05

	debuglog("Waiting for CHAT_STRING REQ cmd (0x0D)\n");
    cmd = 0x0D;
	while ( check_commands_array(cmd)==0 ){
		ret = make_tcp_client_sess1_recv_loop();
        if (ret < 0) { return -1; };
		show_memory(RECV_CHAT_COMMANDS, RECV_CHAT_COMMANDS_LEN, "RECV_CHAT_COMMANDS:");
	};
	debuglog("Got CHAT_STRING REQ OK cmd\n");


    // we need to know remote chat_string here

    // start working with db
    // create start of chain technically message before we get real messages
    // LOCAL_NAME -- author
    // 1 -- is_service
    ret = save_message_to_db(HEADER_ID_LOCAL_FIRST, 0x00, HEADER_ID_LOCAL_FIRST, REMOTE_NAME, LOCAL_NAME, 1);
    if (ret < 0) { return ret; };
    // end of working with db


	// PARAM send10

	global_chatsync_streamid = 0x50D48243;

	memset(buf,0,sizeof(buf));
  	buf_len=encode41_sess1pkt_cmd23_initreq(buf, sizeof(buf));
    do_proto_log(buf, buf_len, "send10");
    make_tcp_client_cmdpkt_wrap(buf, buf_len, "cmd23_initreq");

	// PARAM recv09

	debuglog("Waiting for CHAT STRING SIGNED (NEWBLK1) cmd (0x24)\n");
    cmd = 0x24;
	while ( check_commands_array(cmd)==0 ){
		ret = make_tcp_client_sess1_recv_loop();
        if (ret < 0) { return -1; };
		show_memory(RECV_CHAT_COMMANDS, RECV_CHAT_COMMANDS_LEN, "RECV_CHAT_COMMANDS:");
	};
	debuglog("Got CHAT STRING SIGNED OK cmd\n");

    // PARAM send12

	debuglog("Entering stage1...\n");

	global_chatsync_stage = 1;
	make_tcp_client_sess1_send_req();

    // PARAM send14

	global_chatsync_stage = 1;

	memset(buf,0,sizeof(buf));
  	buf_len=encode41_sess1pkt_cmd0Fsmall_chatok(buf, sizeof(buf));
    do_proto_log(buf, buf_len, "send14");
    make_tcp_client_cmdpkt_wrap(buf, buf_len, "cmd0Fsmall_chatok");

    // PARAM send15

	debuglog("Entering stage2...\n");
	global_chatsync_stage = 2;

	memset(buf,0,sizeof(buf));
    buf_len=encode41_sess1pkt_cmd29_sign2req(buf, sizeof(buf));
    do_proto_log(buf, buf_len, "send15");
    make_tcp_client_cmdpkt_wrap(buf, buf_len, "cmd29_sign2req");

    // PARAM send16

	debuglog("Entering stage3...\n");
	global_chatsync_stage = 3;

    HEADER_ID_SEND = 0xFFFFFFFF;

	memset(buf,0,sizeof(buf));
    buf_len=encode41_sess1pkt_cmd10r_lastmyheader(buf, sizeof(buf));
    do_proto_log(buf, buf_len, "send16");
    make_tcp_client_cmdpkt_wrap(buf, buf_len, "_cmd10r_lastmyheader");

	// PARAM recv17

	debuglog("Waiting for HEADERS SIGNED (NEWBLK2) cmd (0x2A)\n");
    cmd = 0x2A;
	while ( check_commands_array(cmd)==0 ){
		ret = make_tcp_client_sess1_recv_loop();
        if (ret < 0) { return -1; };
		show_memory(RECV_CHAT_COMMANDS, RECV_CHAT_COMMANDS_LEN, "RECV_CHAT_COMMANDS:");
	};
	debuglog("Got HEADERS SIGNED OK cmd\n");

	// PARAM send19

	global_chatsync_stage = 2;
	make_tcp_client_sess1_send_req();

	// PARAM recv19

	debuglog("Waiting for REMOTE HEADERS LIST cmd (0x13)\n");
    cmd = 0x13;
	while ( check_commands_array(cmd)==0 ){
		ret = make_tcp_client_sess1_recv_loop();
        if (ret < 0) { return -1; };
		show_memory(RECV_CHAT_COMMANDS, RECV_CHAT_COMMANDS_LEN, "RECV_CHAT_COMMANDS:");
	};
	debuglog("Got REMOTE HEADERS LIST OK cmd\n");


    msg_count_tmp = HEADER_ID_REMOTE_LAST - HEADER_ID_REMOTE_FIRST;
    debuglog("GOT_REMOTE_MSG_COUNT (05-2F: {00-02: count }): %d\n", GOT_REMOTE_MSG_COUNT);
    debuglog("Calculated msg count based on headers: %d\n", msg_count_tmp);

    if (msg_count_tmp != GOT_REMOTE_MSG_COUNT) {
        debuglog("Not enough headers received. Headers numbers differs from 05-2F msg_count\n");
        //return -1;
    };





    // PARAM send23

	debuglog("Entering stage4...\n");
	global_chatsync_stage = 4;

	//HEADER_ID_SEND = 0x553A6CD3;
    //HEADER_ID_SEND = HEADER_ID_REMOTE_LAST;

	memset(buf,0,sizeof(buf));
    buf_len=encode41_sess1pkt_cmd15r_reqmsgbody(buf, sizeof(buf));
    do_proto_log(buf, buf_len, "send23");
    make_tcp_client_cmdpkt_wrap(buf, buf_len, "_cmd15r_reqmsgbody");

	// PARAM send24

	global_chatsync_stage = 3;
	make_tcp_client_sess1_send_req();

    // PARAM recv24
	// msg body
   
    //clear_msg_file();

	debuglog("Waiting for REMOTE MSG cmd (0x2B)\n");
    cmd = 0x2B;
	while ( check_commands_array(cmd)==0 ){
		ret = make_tcp_client_sess1_recv_loop();
        if (ret < 0) { return -1; };
		show_memory(RECV_CHAT_COMMANDS, RECV_CHAT_COMMANDS_LEN, "RECV_CHAT_COMMANDS:");
	};
	debuglog("Got REMOTE MSG OK cmd\n");

	//
	// todo 
    // add cert decrypt function from cert_decrypt for get pubkey
	// already done?
	//

	// PARAM send26

	global_chatsync_stage = 4;
	make_tcp_client_sess1_send_req();

	// PARAM send28

	debuglog("Entering stage5...\n");
	global_chatsync_stage = 5;

	//HEADER_ID_SEND = 0x553A6CD3;
    HEADER_ID_SEND = HEADER_ID_REMOTE_LAST;

	// should be same, as in cmd13r, cmd15 and cmd2Br
	debuglog("HEADER_ID_SEND: 0x%08X\n", HEADER_ID_SEND);

	memset(buf,0,sizeof(buf));
    buf_len=encode41_sess1pkt_cmd10r_lastmyheader(buf, sizeof(buf));
    do_proto_log(buf, buf_len, "send28");
    make_tcp_client_cmdpkt_wrap(buf, buf_len, "_cmd10r_lastmyheader");

    // PARAM recv28

    // signed header confirmed and signed
	debuglog("Waiting for CHATEND cmd (0x0C)\n");
    cmd = 0x0C;
	while ( check_commands_array(cmd)==0 ){
		ret = make_tcp_client_sess1_recv_loop();
        if (ret < 0) { return -1; };
		show_memory(RECV_CHAT_COMMANDS, RECV_CHAT_COMMANDS_LEN, "RECV_CHAT_COMMANDS:");
	};
	debuglog("Got CHATEND OK cmd\n");

	// PARAM send30

	global_chatsync_stage = 5;
	make_tcp_client_sess1_send_req();

	// PARAM recv29

	debuglog("Waiting for SENDEND cmd (0x13)\n");
    cmd = 0x13;
	while ( check_commands_array(cmd)==0 ){
		ret = make_tcp_client_sess1_recv_loop();
        if (ret < 0) { return -1; };
		show_memory(RECV_CHAT_COMMANDS, RECV_CHAT_COMMANDS_LEN, "RECV_CHAT_COMMANDS:");
	};
	debuglog("Got SENDEND OK cmd\n");

	// PARAM recv30

	debuglog("Waiting for LAST MY HEADER cmd (0x10)\n");
    cmd = 0x10;
	while ( check_commands_array(cmd)==0 ){
		ret = make_tcp_client_sess1_recv_loop();
        if (ret < 0) { return -1; };
		show_memory(RECV_CHAT_COMMANDS, RECV_CHAT_COMMANDS_LEN, "RECV_CHAT_COMMANDS:");
	};
	debuglog("Got LAST MY HEADER OK cmd\n");

	// PARAM send34

	debuglog("Entering stage6...\n");
	global_chatsync_stage = 6;
	make_tcp_client_sess1_send_req();

	// PARAM send36

	global_chatsync_stage = 6;

    // cmd 13 with 3 slots (and 4 local headers in sequence)

    //HEADER_ID_LOCAL_FIRST = 0x27AAA1B0;


    //HEADER_ID_LOCAL_LAST = HEADER_ID_LOCAL_FIRST + 3;

    debuglog("HEADER_ID_REMOTE_FIRST = %08X\n", HEADER_ID_REMOTE_FIRST);
    debuglog("HEADER_ID_REMOTE_LAST = %08X\n", HEADER_ID_REMOTE_LAST);

    if (GOT_REMOTE_MSG_COUNT > 0) {
        HEADER_ID_LOCAL_LAST = HEADER_ID_LOCAL_FIRST + 2 + GOT_REMOTE_MSG_COUNT;

        // special case
        if (HEADER_ID_REMOTE_LAST == HEADER_ID_REMOTE_FIRST) {
            HEADER_ID_LOCAL_LAST = HEADER_ID_LOCAL_FIRST + 2;
        };

    	debuglog("HEADER_ID_LOCAL_FIRST: 0x%08X\n", HEADER_ID_LOCAL_FIRST);
    	debuglog("HEADER_ID_LOCAL_LAST: 0x%08X\n", HEADER_ID_LOCAL_LAST);
        debuglog("HEADER_ID_REMOTE_FIRST = %08X\n", HEADER_ID_REMOTE_FIRST);
        debuglog("HEADER_ID_REMOTE_LAST = %08X\n", HEADER_ID_REMOTE_LAST);

    } else {
        HEADER_ID_LOCAL_LAST = HEADER_ID_LOCAL_FIRST + 3;
    };

    START_HEADER_ID = HEADER_ID_LOCAL_LAST;

    make_tcp_client_prepare_newblk_msg2();
    HEADER_SLOT_CRC3 = get_header_id_crc_cmd24();
    debuglog("HEADER_SLOT_CRC3 = 0x%08X\n", HEADER_SLOT_CRC3);

    //HEADER_SLOT_CRC3 = 0x6ED93068;
    //HEADER_SLOT_CRC3 = 0x6ED93068 + 0x10;


	// randomly generated our local first header_id for this chat
	debuglog("HEADER_ID_LOCAL_FIRST: 0x%08X\n", HEADER_ID_LOCAL_FIRST);
	debuglog("HEADER_ID_LOCAL_LAST: 0x%08X\n", HEADER_ID_LOCAL_LAST);

    debuglog("HEADER_ID_REMOTE_FIRST = %08X\n", HEADER_ID_REMOTE_FIRST);
    debuglog("HEADER_ID_REMOTE_LAST = %08X\n", HEADER_ID_REMOTE_LAST);

    if (HEADER_ID_REMOTE_LAST == 0xFFFFFFFF) {
        debuglog("some err\n");
        return -1;
    };

	memset(buf,0,sizeof(buf));
    buf_len=encode41_sess1pkt_cmd13r2_slotfill(buf, sizeof(buf));
    do_proto_log(buf, buf_len, "send36");
    make_tcp_client_cmdpkt_wrap(buf, buf_len, "_cmd13r2_sendheaders2");


	// PARAM send37

	debuglog("Entering stage7...\n");
	global_chatsync_stage = 7;
	make_tcp_client_sess1_send_req();

	// PARAM recv35

    debuglog("Waiting for HEADER OK (ready for msg) cmd (0x15)\n");
    cmd = 0x15;
	while ( check_commands_array(cmd)==0 ){
		ret = make_tcp_client_sess1_recv_loop();
        if (ret < 0) { return -1; };
		show_memory(RECV_CHAT_COMMANDS, RECV_CHAT_COMMANDS_LEN, "RECV_CHAT_COMMANDS:");
	};
    debuglog("Got HEADER OK (ready for msg) cmd\n");

	// PARAM send40 (MSG PACKET 2)

    START_HEADER_ID = HEADER_ID_LOCAL_LAST;

	debuglog("HEADER_ID_LOCAL_FIRST: 0x%08X\n", HEADER_ID_LOCAL_FIRST);
	debuglog("HEADER_ID_LOCAL_LAST: 0x%08X\n", HEADER_ID_LOCAL_LAST);
    debuglog("HEADER_ID_REMOTE_FIRST = %08X\n", HEADER_ID_REMOTE_FIRST);
    debuglog("HEADER_ID_REMOTE_LAST = %08X\n", HEADER_ID_REMOTE_LAST);

    make_tcp_client_prepare_newblk_msg2();

	memset(buf,0,sizeof(buf));
    buf_len=encode41_sess1pkt_cmd2Br_msgbody(buf, sizeof(buf));
    do_proto_log(buf, buf_len, "send40");
    do_proto_log_cryptodecode(buf, buf_len, "send40_signed_decode");
    make_tcp_client_cmdpkt_wrap(buf, buf_len, "_cmd2Br_msgbody");

	// PARAM send41

	debuglog("Entering stage8...\n");
	global_chatsync_stage = 8;
	make_tcp_client_sess1_send_req();

	// PARAM recv41

    debuglog("Waiting for UIC REQUEST cmd (0x1D)\n");
    cmd = 0x1D;
	while ( check_commands_array(cmd)==0 ){
		ret = make_tcp_client_sess1_recv_loop();
        if (ret < 0) { return -1; };
		show_memory(RECV_CHAT_COMMANDS, RECV_CHAT_COMMANDS_LEN, "RECV_CHAT_COMMANDS:");
	};
    debuglog("Got UIC REQUEST cmd\n");

	// PARAM send44

	memset(buf,0,sizeof(buf));
    buf_len=encode41_sess1pkt_cmd1E_uicreply(buf, sizeof(buf));
    do_proto_log(buf, buf_len, "send44");
    make_tcp_client_cmdpkt_wrap(buf, buf_len, "_cmd1E_uicreply");

	// PARAM send45

	debuglog("Entering stage9...\n");
	global_chatsync_stage = 9;
	make_tcp_client_sess1_send_req();

	// PARAM recv45

	debuglog("Waiting for LAST MY HEADER cmd (0x10)\n");
    cmd = 0x10;
	while ( check_commands_array(cmd)==0 ){
		ret = make_tcp_client_sess1_recv_loop();
        if (ret < 0) { return -1; };
		show_memory(RECV_CHAT_COMMANDS, RECV_CHAT_COMMANDS_LEN, "RECV_CHAT_COMMANDS:");
	};
	debuglog("Got LAST MY HEADER OK cmd\n");

    // PARAM send48

	global_chatsync_stage = 9;

	memset(buf,0,sizeof(buf));
    buf_len=encode41_sess1pkt_cmd13r3_sendheaders3(buf, sizeof(buf));
    do_proto_log(buf, buf_len, "send48");
    make_tcp_client_cmdpkt_wrap(buf, buf_len, "_cmd13r3_sendheaders3");

    // PARAM send49

	debuglog("Entering stage 0x0A...\n");
	global_chatsync_stage = 0x0A;

	HEADER_ID_SEND = HEADER_ID_REMOTE_LAST;

	memset(buf,0,sizeof(buf));
    buf_len=encode41_sess1pkt_cmd10r_pos2(buf, sizeof(buf));
    do_proto_log(buf, buf_len, "send49");
    make_tcp_client_cmdpkt_wrap(buf, buf_len, "_cmd10r_pos2");
    
    // PARAM send50

	debuglog("Entering stage 0x0A...\n");
	global_chatsync_stage = 0x0A;
	make_tcp_client_sess1_send_req();

    // PARAM recv49

	debuglog("Waiting for SENDEND cmd (0x13)\n");
    cmd = 0x13;
	while ( check_commands_array(cmd)==0 ){
		ret = make_tcp_client_sess1_recv_loop();
        if (ret < 0) { return -1; };
		show_memory(RECV_CHAT_COMMANDS, RECV_CHAT_COMMANDS_LEN, "RECV_CHAT_COMMANDS:");
	};
	debuglog("Got SENDEND OK cmd\n");

    // PARAM send54

	debuglog("Entering stage 0x0B...\n");
	global_chatsync_stage = 0x0B;

    debuglog("new HEADER_ID_REMOTE_FIRST = %08X\n", HEADER_ID_REMOTE_FIRST);
    debuglog("new HEADER_ID_REMOTE_LAST = %08X\n", HEADER_ID_REMOTE_LAST);

	HEADER_ID_SEND = HEADER_ID_REMOTE_LAST;

	memset(buf,0,sizeof(buf));
    buf_len=encode41_sess1pkt_cmd10r_pos2(buf, sizeof(buf));
    do_proto_log(buf, buf_len, "send54");
    make_tcp_client_cmdpkt_wrap(buf, buf_len, "_cmd10r_pos2");

    // PARAM send55

	global_chatsync_stage = 0x0B;
	make_tcp_client_sess1_send_req();

    // PARAM recv53

	debuglog("Waiting for SYNC FINISH (0x27)\n");
    cmd = 0x27;
	while ( check_commands_array(cmd)==0 ){
		ret = make_tcp_client_sess1_recv_loop();
        if (ret < 0) { return -1; };
		show_memory(RECV_CHAT_COMMANDS, RECV_CHAT_COMMANDS_LEN, "RECV_CHAT_COMMANDS:");
	};
	debuglog("Got SYNC FINISH OK cmd\n");

    ///////////////// stop here and do some checks? //////

    // PARAM send57

	debuglog("Entering stage 0x0C...\n");
	global_chatsync_stage = 0x0C;

    // just do same
    // move in get_01_36_blob
    //memcpy(HEADER_ID_CMD27_CRC, rnd64bit, 4);
	//memcpy(HEADER_ID_CMD27_ID, rnd64bit+4, 4);


    // good
    //HEADER_ID_CMD27_CRC = HEADER_SLOT_CRC3;
    //HEADER_ID_CMD27_ID = HEADER_ID_LOCAL_LAST;

	memset(buf,0,sizeof(buf));
    buf_len=encode41_sess1pkt_cmd27r(buf, sizeof(buf));
    do_proto_log(buf, buf_len, "send57");
    make_tcp_client_cmdpkt_wrap(buf, buf_len, "_cmd27r");

	// PARAM send59

	global_chatsync_stage = 0x0C;
	make_tcp_client_sess1_send_req();

    //
    // should wait for pkt_error
    //

	// PARAM recv57

    /*
	memset(buf,0,sizeof(buf));
    buf_len=encode41_sess1pkt_error(buf, sizeof(buf));
    make_tcp_client_cmdpkt_wrap(buf, buf_len, "_error and close");
    */

    make_tcp_client_sess1_recv_loop();

    //make_tcp_client_sess1_recv_loop();
    //make_tcp_client_sess1_recv_loop();
    //save_good_remote_chatstring();


    // PARAM sendXXX

    global_chatsync_stage = 0;

	memset(buf,0,sizeof(buf));
  	buf_len=encode41_sess1pkt_cmd1B(buf, sizeof(buf));
    do_proto_log(buf, buf_len, "sendXXX");
    make_tcp_client_cmdpkt_wrap(buf, buf_len, "cmd1B_closeconnection");

    // END OF CONNECTION CLOSE PKT

    ret = make_tcp_client_sess1_recv_loop();
    if (ret < 0) { return ret; };


    save_chatstring_to_db();

	//save_good_lastsync(HEADER_ID_CMD27_ID, HEADER_ID_CMD27_CRC);
    //save_good_localheaders(HEADER_ID_LOCAL_LAST, 0x00000000);

    // close_connection();

    debuglog("\nMSG RECV OK!\n");
    debuglog("FULL _INIT_ CHAT SESSION SYNC OK!\n");
    debuglog("_INIT_ CHAT SESSION SYNC-ed!\n");

    /*
	debuglog("Waiting for ... (infinite)\n");
	while (1){
		ret = make_tcp_client_sess1_recv_loop();
        if (ret < 0) { return -1; };
	};
    */

    return 1;
};

