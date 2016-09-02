//
// new chat init session pkts
//
#include <stdio.h>
#include <stdlib.h>

#include "short_types.h"

extern unsigned int get_header_id_crc_cmd24();

extern u8 REMOTE_NAME[0x100];
extern u8 LOCAL_NAME[0x100];
extern u8 MSG_TEXT[0x1000];

extern uint HEADER_ID_REMOTE_FIRST;
extern uint HEADER_ID_REMOTE_LAST;

extern uint HEADER_ID_SEND;
extern uint HEADER_ID_SEND_CRC;
extern uint START_HEADER_ID;

extern uint NEWSESSION_FLAG;
extern uint NO_HEADERS_FLAG;

extern uint global_chatsync_stage;

extern u8 RECV_CHAT_COMMANDS[0x100];
extern uint RECV_CHAT_COMMANDS_LEN;

extern int newchatinit_flag;
extern int restorechat_flag;

// init params
extern uint global_chatsync_streamid;

extern uint global_msg_time_sec;
extern uint global_msg_time_min;

extern uint pkt_7D_BLOB_00_01;
extern uint pkt_7D_BLOB_00_19;

extern uint pkt_7A_BLOB_00_13;

extern uint pkt_cmd24_BLOB_00_1B;
extern uint pkt_cmd24_BLOB_00_00;
extern uint global_unknown_cmd24_signed_id;

extern uint pkt_cmd2A_BLOB_00_00;
extern uint global_unknown_cmd2A_signed_id;

extern uint pkt_cmd13_BLOB_00_0F;

extern uint pkt_cmd2B_BLOB_00_00;

extern uint HEADER_SLOT_CRC1;
extern uint HEADER_SLOT_CRC2;
extern uint HEADER_SLOT_CRC3;

extern int relay_connect_mode;

// end of init params


unsigned int do_sync_session_close() {
	u8 buf[0x1000];
	int buf_len;
	int ret;

	debuglog_info("Sending close session packet\n\n");

	memset(buf,0,sizeof(buf));
    buf_len = encode41_sess1pkt_error(buf, sizeof(buf));
    do_proto_log(buf, buf_len, "send_error_and_close");
    make_tcp_client_cmdpkt_wrap(buf, buf_len, "_error_and_close");

	return 0;
};


unsigned int send_newchatinit_pkts() {
	u8 buf[0x1000];
	int buf_len;
    unsigned int cmd;
    int ret;
    
    debuglog_info("Do send_newchatinit_pkts() send...\n");   

    newchatinit_flag = 1;

    NO_HEADERS_FLAG = 0;
    NEWSESSION_FLAG = 0;

    memset(RECV_CHAT_COMMANDS, 0x00, RECV_CHAT_COMMANDS_LEN);
    RECV_CHAT_COMMANDS_LEN = 0;


    //
    // initialize protocol parameters
    //

    //memcpy(LOCALNODE_VCARD,"\xE0\x3E\x31\xAE\x40\x3A\xE0\x12\x00\x75\x03\x25\xC7\xE1\x08\x41\x37\xDF\x19\x9C\x55\xC0\xA8\x01\x4B\xE1\x08",0x1B);

    // unix timestamp in seconds
    //global_msg_time_sec = 0x56968716;
    //global_msg_time_sec = 0x5696870E;
    global_msg_time_sec = time(NULL);

    // unix timestamp in minutes
    //global_msg_time_min = 0x0171710D;
    global_msg_time_min = time(NULL) / 60;

    global_chatsync_streamid = 0xD3E1751B;

    pkt_7D_BLOB_00_01 = 02;
    pkt_7D_BLOB_00_19 = 0xF0;

	pkt_7A_BLOB_00_13 = 0x8CBC998D;

    pkt_cmd24_BLOB_00_1B = 0x0A;
    pkt_cmd24_BLOB_00_00 = 0x0B;
    global_unknown_cmd24_signed_id = 0x40F220AE;

    pkt_cmd2A_BLOB_00_00 = 0x0B;
    global_unknown_cmd2A_signed_id = 0x21176632;

    // C7 88 8F 54
    START_HEADER_ID=0x548F88C7;

    pkt_cmd13_BLOB_00_0F = START_HEADER_ID;

    pkt_cmd2B_BLOB_00_00 = 03;


    // new chat_string -- new slot_crc
    // calculated later, before cmd24 send
    //HEADER_SLOT_CRC1 = 0xB6470243;
    //HEADER_SLOT_CRC2 = 0x2C75AB25;
    // not used
    HEADER_SLOT_CRC3 = 0x00;

    // first init session chat_string_id
    make_tcp_client_prepare_chatinit();

    ret = make_tcp_client_prepare_newblk_chatsign();
    if (ret < 0) { return -1; };
    HEADER_SLOT_CRC1 = get_header_id_crc_cmd24();
    debuglog("HEADER_SLOT_CRC1 = 0x%08X\n", HEADER_SLOT_CRC1);

    ret = make_tcp_client_prepare_newblk_msg();
    if (ret < 0) { return -1; };
    HEADER_SLOT_CRC2 = get_header_id_crc_cmd24();
    debuglog("HEADER_SLOT_CRC2 = 0x%08X\n", HEADER_SLOT_CRC2);


    //
    // end of initialize protocol parameters
    //

    // start working with db

    // saving new prepared msg to db with our local_header_id.
    // its test message which was not sended
    // LOCAL_NAME -- author
    // is_service_only -- service flag
    ret = save_message_to_db(START_HEADER_ID, HEADER_SLOT_CRC1, START_HEADER_ID, REMOTE_NAME, LOCAL_NAME, 1);
    if (ret < 0) { return ret; };

    // this is actual message 
    // which will be sended by us
    ret = save_message_to_db(START_HEADER_ID+1, HEADER_SLOT_CRC2, START_HEADER_ID+1, MSG_TEXT, LOCAL_NAME, 0);
    if (ret < 0) { return ret; };

    // end work with db


    debuglog("Entering stage0...\n");
    global_chatsync_stage = 0;

	// PARAM send06

	memset(buf,0,sizeof(buf));
  	buf_len=encode41_sess1pkt_7D(buf, sizeof(buf));
    do_proto_log(buf, buf_len, "send06");
    make_tcp_client_cmdpkt_wrap(buf, buf_len, "sess1pkt_7D");

	// PARAM send07

	memset(buf,0,sizeof(buf));
  	buf_len=encode41_sess1pkt_7A(buf, sizeof(buf));
    do_proto_log(buf, buf_len, "send07");
    make_tcp_client_cmdpkt_wrap(buf, buf_len, "sess1pkt_7A");

	// PARAM send08

	memset(buf,0,sizeof(buf));
  	buf_len=encode41_sess1pkt_cmd0D(buf, sizeof(buf));
    do_proto_log(buf, buf_len, "send08");
    make_tcp_client_cmdpkt_wrap(buf, buf_len, "cmd0D_chatinit");

    //addon for tests
	//make_tcp_client_sess1_send_7B();
	//make_tcp_client_sess1_send_58();


    // PARAM recv10

    debuglog("Waiting for CHAT_STRING INIT OK cmd (0x23)\n");
    // should recv 0x23 // newchat sign request
    cmd = 0x23;
	while ( check_commands_array(cmd)==0 ){
		ret = make_tcp_client_sess1_recv_loop();
        if (ret < 0) { return -1; };
		show_memory(RECV_CHAT_COMMANDS, RECV_CHAT_COMMANDS_LEN, "RECV_CHAT_COMMANDS:");
	};
    debuglog("Got CHAT_STRING INIT OK cmd\n");
    // chat init ok

    debuglog("Entering stage1...\n");
    global_chatsync_stage = 1;

    // PARAM send12

    ret = make_tcp_client_prepare_newblk_chatsign();
    if (ret < 0) { return -1; };

	memset(buf,0,sizeof(buf));
  	buf_len=encode41_sess1pkt_cmd24(buf, sizeof(buf));
    do_proto_log(buf, buf_len, "send12");
    do_proto_log_cryptodecode(buf, buf_len, "send12_signed_decode");
    make_tcp_client_cmdpkt_wrap(buf, buf_len, "cmd24_chatstring_sign");

    // PARAM send13

    global_chatsync_stage = 0;
    make_tcp_client_sess1_send_req();

    // PARAM recv14

    debuglog("Waiting for CHAT_STRING SIGN OK (0x0F)\n");
    // should recv 0x0F
    cmd = 0x0F;
    while ( check_commands_array(cmd)==0 ){
        ret = make_tcp_client_sess1_recv_loop();
        if (ret < 0) { return ret; };
        show_memory(RECV_CHAT_COMMANDS, RECV_CHAT_COMMANDS_LEN, "RECV_CHAT_COMMANDS:");
    };
    debuglog("Got CHAT_STRING SIGN OK cmd\n");

    // PARAM send16

    global_chatsync_stage = 1;
    make_tcp_client_sess1_send_req();

    // PARAM recv15

    debuglog("Waiting for HEADERS SIGN request cmd (0x29)\n");
    // should recv 0x29
    cmd = 0x29;
    while ( check_commands_array(cmd)==0 ){
        ret = make_tcp_client_sess1_recv_loop();
        if (ret < 0) { return ret; };
        show_memory(RECV_CHAT_COMMANDS, RECV_CHAT_COMMANDS_LEN, "RECV_CHAT_COMMANDS:");
    };
    debuglog("Got HEADERS SIGN request cmd\n");

    // PARAM recv16

    debuglog("Waiting for HEADERS SIGN OK cmd (0x10)\n");
    // should recv 0x10
    cmd = 0x10;
    while ( check_commands_array(cmd)==0 ){
        ret = make_tcp_client_sess1_recv_loop();
        if (ret < 0) { return ret; };
        show_memory(RECV_CHAT_COMMANDS, RECV_CHAT_COMMANDS_LEN, "RECV_CHAT_COMMANDS:");
    };
    debuglog("Got HEADERS SIGN OK cmd\n");

    // PARAM send20

    global_chatsync_stage = 2;
    ret = make_tcp_client_prepare_newblk_headsign();
    if (ret < 0) { return -1; };

	memset(buf,0,sizeof(buf));
  	buf_len=encode41_sess1pkt_cmd2A(buf, sizeof(buf));
    do_proto_log(buf, buf_len, "send20");
    do_proto_log_cryptodecode(buf, buf_len, "send20_signed_decode");
    make_tcp_client_cmdpkt_wrap(buf, buf_len, "cmd2A_headsign");

    // PARAM send21

    make_tcp_client_sess1_send_req();

    // PARAM send23

    global_chatsync_stage=3;

	memset(buf,0,sizeof(buf));
  	buf_len=encode41_sess1pkt_cmd13(buf, sizeof(buf));
    do_proto_log(buf, buf_len, "send23");
    make_tcp_client_cmdpkt_wrap(buf, buf_len, "cmd13_sendheaders");

    // PARAM send24

    make_tcp_client_sess1_send_req();

    // PARAM recv22

    debuglog("Waiting for HEADER OK (ready for msg) cmd (0x15)\n");
    // should recv 0x15
    cmd = 0x15;
    while ( check_commands_array(cmd)==0 ){
        ret = make_tcp_client_sess1_recv_loop();
        if (ret < 0) { return ret; };
        show_memory(RECV_CHAT_COMMANDS, RECV_CHAT_COMMANDS_LEN, "RECV_CHAT_COMMANDS:");
    };
    debuglog("Got HEADER OK (ready for msg) cmd\n");

    // PARAM send27

    debuglog("Entering stage4...\n");
    global_chatsync_stage = 4;
    ret = make_tcp_client_prepare_newblk_msg();
    if (ret < 0) { return -1; };

	memset(buf,0,sizeof(buf));
  	buf_len=encode41_sess1pkt_cmd2B(buf, sizeof(buf));
    do_proto_log(buf, buf_len, "send27");
    do_proto_log_cryptodecode(buf, buf_len, "send27_signed_decode");
    make_tcp_client_cmdpkt_wrap(buf, buf_len, "cmd2B_send_msgbody");

    // PARAM send28

    make_tcp_client_sess1_send_req();

    // PARAM recv28

    debuglog("Waiting for SECOND HEADERS SIGN OK cmd (0x10)\n");
    // should recv 0x10
    cmd = 0x10;
    while ( check_commands_array(cmd)==0 ){
        ret = make_tcp_client_sess1_recv_loop();
        if (ret < 0) { return ret; };
        show_memory(RECV_CHAT_COMMANDS, RECV_CHAT_COMMANDS_LEN, "RECV_CHAT_COMMANDS:");
    };
    debuglog("Got SECOND HEADERS SIGN OK cmd\n");

    // PARAM send31

    debuglog("Entering stage5...\n");
    global_chatsync_stage = 5;

	memset(buf,0,sizeof(buf));
  	buf_len=encode41_sess1pkt_cmd0C(buf, sizeof(buf));
    do_proto_log(buf, buf_len, "send31");
    make_tcp_client_cmdpkt_wrap(buf, buf_len, "cmd0C_chatend");

    // PARAM send32

    global_chatsync_stage = 6;

	memset(buf,0,sizeof(buf));
  	buf_len=encode41_sess1pkt_cmd13end(buf, sizeof(buf));
    do_proto_log(buf, buf_len, "send32");
    make_tcp_client_cmdpkt_wrap(buf, buf_len, "cmd13end_sendend");

    // it seems we need to sync too, starting a syncing loop
    // NEGOTIATING->SYNCING
    // has_more_to_sync: no need to sync at all: 16352baa; lmid = 16352baa
    // SYNCER - ffffffff - 0 - 0 - 0 - 0

    // PARAM send33

    global_chatsync_stage = 7;

    HEADER_ID_SEND = 0xFFFFFFFF;

	memset(buf,0,sizeof(buf));
  	buf_len=encode41_sess1pkt_cmd10(buf, sizeof(buf));
    do_proto_log(buf, buf_len, "send33");
    make_tcp_client_cmdpkt_wrap(buf, buf_len, "cmd10_send_unkheader");

    // PARAM send34

    global_chatsync_stage = 5;
    make_tcp_client_sess1_send_req();

    // PARAM recv35

    HEADER_ID_REMOTE_LAST = 0;
    HEADER_ID_SEND = 0;

    debuglog("Waiting for REMOTE SEND HEADERS cmd (0x13)\n");
    // should recv 0x13
    cmd = 0x13;
    while ( check_commands_array(cmd)==0 ){
        ret = make_tcp_client_sess1_recv_loop();
        if (ret < 0) { return ret; };
        show_memory(RECV_CHAT_COMMANDS, RECV_CHAT_COMMANDS_LEN, "RECV_CHAT_COMMANDS:");
    };
    debuglog("Got REMOTE SEND HEADERS OK cmd\n");

    debuglog("HEADER_ID_SEND (remote): 0x%08X\n",HEADER_ID_SEND);

    // PARAM send38

    global_chatsync_stage = 8;

	memset(buf,0,sizeof(buf));
  	buf_len=encode41_sess1pkt_cmd15(buf, sizeof(buf));
    do_proto_log(buf, buf_len, "send38");
    make_tcp_client_cmdpkt_wrap(buf, buf_len, "cmd15");

    // PARAM send39

    global_chatsync_stage = 6;
    make_tcp_client_sess1_send_req();

    // recv38

    debuglog("Waiting for REMOTE MSG BODY cmd (0x2B)\n");
    // should recv 0x2B
    cmd = 0x2B;
    while ( check_commands_array(cmd)==0 ){
        ret = make_tcp_client_sess1_recv_loop();
        if (ret < 0) { return ret; };
        show_memory(RECV_CHAT_COMMANDS, RECV_CHAT_COMMANDS_LEN, "RECV_CHAT_COMMANDS:");
    };
    debuglog("Got REMOTE MSG BODY OK cmd\n");

    // PARAM send42

    global_chatsync_stage = 7;
    make_tcp_client_sess1_send_req();

    // PARAM send44

    global_chatsync_stage = 9;

	memset(buf,0,sizeof(buf));
  	buf_len=encode41_sess1pkt_cmd1D(buf, sizeof(buf));
    do_proto_log(buf, buf_len, "send44");
    make_tcp_client_cmdpkt_wrap(buf, buf_len, "cmd1D_request_uic");

    // PARAM recv43

    debuglog("Waiting for UIC REPLY cmd (0x1E)\n");
    cmd = 0x1E;
    while ( check_commands_array(cmd)==0 ){
        ret = make_tcp_client_sess1_recv_loop();
        if (ret < 0) { return ret; };
        show_memory(RECV_CHAT_COMMANDS, RECV_CHAT_COMMANDS_LEN, "RECV_CHAT_COMMANDS:");
    };
    debuglog("Got UIC REPLY OK cmd\n");

    // PARAM send46

    global_chatsync_stage = 8;
    make_tcp_client_sess1_send_req();

    // PARAM send48

    global_chatsync_stage = 0x0A;
    debuglog("HEADER_ID_SEND (remote): 0x%08X\n",HEADER_ID_SEND);

	memset(buf,0,sizeof(buf));
  	buf_len=encode41_sess1pkt_cmd10(buf, sizeof(buf));
    do_proto_log(buf, buf_len, "send48");
    make_tcp_client_cmdpkt_wrap(buf, buf_len, "cmd10_send_unkheader");

    // PARAM recv47

    debuglog("Waiting for onHereIsExtraData (0x46)\n");
    cmd = 0x46;
    while ( check_commands_array(cmd)==0 ){
        ret = make_tcp_client_sess1_recv_loop();
        if (ret < 0) { return ret; };
        show_memory(RECV_CHAT_COMMANDS, RECV_CHAT_COMMANDS_LEN, "RECV_CHAT_COMMANDS:");
    };
    debuglog("Got onHereIsExtraData OK cmd\n");

    // PARAM send50

    global_chatsync_stage = 9;
    make_tcp_client_sess1_send_req();

    // PARAM recv48

    // releasing syncing hold
    // finishing now, he_is_done = 1
    // SYNCING->WAITING_END

    debuglog("Waiting for SYNC FINISH (0x27)\n");
    cmd = 0x27;
    while ( check_commands_array(cmd)==0 ){
        ret = make_tcp_client_sess1_recv_loop();
        if (ret < 0) { return ret; };
        show_memory(RECV_CHAT_COMMANDS, RECV_CHAT_COMMANDS_LEN, "RECV_CHAT_COMMANDS:");
    };
    debuglog("Got SYNC FINISH OK cmd\n");

    debuglog("HEADER_ID_SEND: 0x%08X\n", HEADER_ID_SEND);
    debuglog("HEADER_ID_SEND_CRC: 0x%08X\n", HEADER_ID_SEND_CRC);

    // PARAM send52

    global_chatsync_stage = 0x0B;

	memset(buf,0,sizeof(buf));
  	buf_len=encode41_sess1pkt_cmd27(buf, sizeof(buf));
    do_proto_log(buf, buf_len, "send52");
    make_tcp_client_cmdpkt_wrap(buf, buf_len, "cmd27_finish");

    // PARAM send53

    global_chatsync_stage = 0x0A;
    make_tcp_client_sess1_send_req();

    // PARAM recv53

    // needed wait for sync close pkt
    debuglog("Waiting for close packet (and negative ret)\n");
    ret = 1;
    while (ret>0){
        ret = make_tcp_client_sess1_recv_loop();
    };


    /*
    if (ret != -20) {
        debuglog("Some error on getting close pkt.\n");
    }
    */


    // all ok got close packet


    // PARAM sendXXX

    global_chatsync_stage = 0;

	memset(buf,0,sizeof(buf));
  	buf_len=encode41_sess1pkt_cmd1B(buf, sizeof(buf));
    do_proto_log(buf, buf_len, "sendXXX");
    make_tcp_client_cmdpkt_wrap(buf, buf_len, "cmd1B_closeconnection");

    // END OF CONNECTION CLOSE PKT

    // no need for direct connect
    if (relay_connect_mode) {
        ret = make_tcp_client_sess1_recv_loop();
        if (ret < 0) { return ret; };
    };

    save_chatstring_to_db();

    debuglog_info("MSG SEND OK!\n");
    debuglog_info("FULL _INIT_ CHAT SESSION SYNC OK!\n");
    debuglog_info("_INIT_ CHAT SESSION SYNC-ed!\n");

    return 1;
};

