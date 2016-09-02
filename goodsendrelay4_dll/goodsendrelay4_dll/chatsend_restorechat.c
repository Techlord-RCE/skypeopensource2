//
// restore chat session pkts
//
#include <stdio.h>
#include <stdlib.h>

#include "short_types.h"

extern u8 REMOTE_NAME[0x100];
extern u8 LOCAL_NAME[0x100];
extern u8 MSG_TEXT[0x1000];

extern uint HEADER_ID_REMOTE_FIRST;
extern uint HEADER_ID_REMOTE_LAST;

extern uint HEADER_ID_LOCAL_FIRST;
extern uint HEADER_ID_LOCAL_LAST;

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

extern int global_cmd10_needsync_flag;

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

extern uint HEADER_ID_CMD27_CRC;
extern uint HEADER_ID_CMD27_ID;

extern int relay_connect_mode;

// end of init params


unsigned int send_chatrestore_pkts() {
	u8 buf[0x1000];
	int buf_len;
    unsigned int cmd;
    unsigned int tmp;
    int ret;

    debuglog_info("Do send_chatrestore_pkts() send...\n");   

    restorechat_flag = 1;

    memset(RECV_CHAT_COMMANDS, 0x00, RECV_CHAT_COMMANDS_LEN);
    RECV_CHAT_COMMANDS_LEN = 0;

    HEADER_ID_REMOTE_LAST = 0;
    HEADER_ID_SEND = 0;

    //
    // initialize protocol parameters
    //

    //memcpy(LOCALNODE_VCARD,"\xE0\x3E\x31\xAE\x40\x3A\xE0\x12\x00\x75\x03\x25\xC7\xE1\x08\x41\x37\xDF\x19\x9C\x55\xC0\xA8\x01\x4B\xE1\x08",0x1B);

    // unix timestamp in seconds
    global_msg_time_sec = time(NULL);

    // unix timestamp in minutes
    global_msg_time_min = time(NULL) / 60;

    global_chatsync_streamid = 0xA3DD389C;

    pkt_7D_BLOB_00_01 = 02;
    pkt_7D_BLOB_00_19 = 0x6E;

	pkt_7A_BLOB_00_13 = 0x1C396851;

    // need for cmd13 after get it in cmd10
    pkt_cmd2B_BLOB_00_00 = 02;

    /*
    // but also need to compare against local sqllite db last header_id
    // C9 88 8F 54
    START_HEADER_ID=0x548F88C9;
    // we dont know last local header_id. So, get it from remote
    pkt_cmd13_BLOB_00_0F = START_HEADER_ID;

    // new chat_string -- new slot_crc
    HEADER_SLOT_CRC1 = 0x40311366;
    ret = make_tcp_client_prepare_newblk_msg();
    if (ret < 0) { return -1; };

    HEADER_SLOT_CRC1 = get_header_id_crc_cmd24();
    debuglog("HEADER_SLOT_CRC1 = 0x%08X\n", HEADER_SLOT_CRC1);
    */


    //
    // end of initialize protocol parameters
    //


    // start work with sql

    // load last local_header_id
    ret = load_localheaders_from_db(&HEADER_ID_LOCAL_FIRST, &tmp);
	if (ret == -1) {
		debuglog_err("Loading LASTSYNC data failed.\n");
		return -1;
	};
    HEADER_ID_LOCAL_FIRST = HEADER_ID_LOCAL_FIRST + 1;
    HEADER_ID_LOCAL_LAST = HEADER_ID_LOCAL_FIRST;

    // we need get last sync headers before we add our new msg with headers 
    // (bef cmd13one)
	ret = load_lastsync_from_db(&HEADER_ID_CMD27_ID, &HEADER_ID_CMD27_CRC);
	if (ret == -1) {
		debuglog_err("Loading LASTSYNC data failed.\n");
		return -1;
	};
    debuglog_info("Loaded lastsync remote_header_id (from msg2): 0x%08X\n", HEADER_ID_SEND);

    // end work with sql


    debuglog_info("Entering stage0...\n");
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

    // PARAM recv12

    debuglog("Waiting for CHAT_STRING INIT OK cmd (0x0F)\n");
    cmd = 0x0F;
    while ( check_commands_array(cmd)==0 ){
        ret = make_tcp_client_sess1_recv_loop();
        if (ret < 0) { return ret; };
        show_memory(RECV_CHAT_COMMANDS, RECV_CHAT_COMMANDS_LEN, "RECV_CHAT_COMMANDS:");
    };
    debuglog("Got CHAT_STRING INIT OK cmd\n");

    // PARAM send13

    global_chatsync_stage = 0;
    make_tcp_client_sess1_send_req();

    // PARAM recv13

    // hm... in wait 0x0F we do processing of all packets, and also cmd10.
    //HEADER_ID_REMOTE_LAST = 0;

    debuglog("Waiting for LAST KNOWN HEADER ID cmd (0x10)\n");
    cmd = 0x10;
    while ( check_commands_array(cmd)==0 ){
        ret = make_tcp_client_sess1_recv_loop();
        if (ret < 0) { return ret; };
        show_memory(RECV_CHAT_COMMANDS, RECV_CHAT_COMMANDS_LEN, "RECV_CHAT_COMMANDS:");
    };
    debuglog("Got LAST KNOWN HEADER ID OK cmd\n");

    debuglog("HEADER_ID_REMOTE_LAST: 0x%08X\n", HEADER_ID_REMOTE_LAST);



    // not need, but need to compare against local sqllite db last header_id
    // C8 88 8F 54
    //START_HEADER_ID=0x548F88C8;
    START_HEADER_ID = HEADER_ID_REMOTE_LAST;

    // we dont know last local header_id. So, get it from remote
    pkt_cmd13_BLOB_00_0F = START_HEADER_ID;

    // new chat_string -- new slot_crc
    HEADER_SLOT_CRC1 = 0x40311366;
    ret = make_tcp_client_prepare_newblk_msg();
    if (ret < 0) { return -1; };
    HEADER_SLOT_CRC1 = get_header_id_crc_cmd24();
    debuglog("HEADER_SLOT_CRC1 = 0x%08X\n", HEADER_SLOT_CRC1);


    // start working with db
    // this is actual message which will be sended by us
    // with predicted remote_header_id
    // LOCAL_NAME -- author
    // 0 -- is_service
    ret = save_message_to_db(HEADER_ID_LOCAL_FIRST, HEADER_SLOT_CRC1, HEADER_ID_CMD27_ID+1, MSG_TEXT, LOCAL_NAME, 0);
    if (ret < 0) { return ret; };
    // end work with db


    // PARAM send15

    debuglog("Entering stage1...\n");
    global_chatsync_stage=1;

    //
    // use HEADER_ID_REMOTE_LAST and HEADER_ID_REMOTE_LAST + 1 for cmd13
    // from cmd10
    // but need use sqllite db for fill it
    //

	memset(buf,0,sizeof(buf));
  	buf_len=encode41_sess1pkt_cmd13one(buf, sizeof(buf));
    do_proto_log(buf, buf_len, "send15");
    make_tcp_client_cmdpkt_wrap(buf, buf_len, "cmd13one");

    // PARAM send16
    
    global_chatsync_stage=1;
    make_tcp_client_sess1_send_req();

    // PARAM recv16

    HEADER_ID_SEND = 0;
    debuglog("Waiting for READY_FOR_MSG cmd (0x15)\n");
    cmd = 0x15;
    while ( check_commands_array(cmd)==0 ){
        ret = make_tcp_client_sess1_recv_loop();
        if (ret < 0) { return ret; };
        show_memory(RECV_CHAT_COMMANDS, RECV_CHAT_COMMANDS_LEN, "RECV_CHAT_COMMANDS:");
    };
    debuglog("Got READY_FOR_MSG OK cmd\n");


    // the HEADER_ID_SEND we got from cmd15 recv parsing
    // msg creating pkt 
    START_HEADER_ID = HEADER_ID_SEND;
    // because in pkt creation we use START_HEADER_ID + 1
    // and in newblk3 also
    START_HEADER_ID--;
    debuglog("START_HEADER_ID: 0x%08X\n", START_HEADER_ID);

    // PARAM send19

    debuglog("Entering stage2...\n");

    global_chatsync_stage = 2;
    ret = make_tcp_client_prepare_newblk_msg();
    if (ret < 0) { return -1; };

	memset(buf,0,sizeof(buf));
  	buf_len=encode41_sess1pkt_cmd2B(buf, sizeof(buf));
    do_proto_log(buf, buf_len, "send19");
    make_tcp_client_cmdpkt_wrap(buf, buf_len, "cmd2B_send_msgbody");

    // PARAM send20

    global_chatsync_stage = 2;
    make_tcp_client_sess1_send_req();

    // PARAM recv21
    // (new) PARAM recv26 from seqrecvsend (sproto) from 26.12.2015

    // for send-recv or recv-send case
    // need to know, if cmd10recv have "00-25: 01" blob as need sync flag
    global_cmd10_needsync_flag = 0;

    // because in cmd10 we got it
    HEADER_ID_REMOTE_LAST = 0;
    debuglog("Waiting for LAST KNOWN HEADER ID cmd (0x10)\n");
    cmd = 0x10;
    while ( check_commands_array(cmd)==0 ){
        ret = make_tcp_client_sess1_recv_loop();
        if (ret < 0) { return ret; };
        show_memory(RECV_CHAT_COMMANDS, RECV_CHAT_COMMANDS_LEN, "RECV_CHAT_COMMANDS:");
    };
    debuglog("Got LAST KNOWN HEADER ID OK cmd\n");

    //
    // if got HEADER_ID_SEND in cmd10 msg sended ok.
    //

    // special case for send-recv or recv-send
    // when we need sync headers
    // if call it, we need return, because send chatrestore protocol done then

    if (global_cmd10_needsync_flag) {
        ret = do_alternative_restorechat_send_final_with_sync();
        return ret;
    };

    // PARAM send24

    debuglog("Entering stage3...\n");
    global_chatsync_stage = 3;

	memset(buf,0,sizeof(buf));
    buf_len=encode41_sess1pkt_cmd46(buf, sizeof(buf));
    do_proto_log(buf, buf_len, "send24");
    make_tcp_client_cmdpkt_wrap(buf, buf_len, "cmd46");

    // PARAM send25

    debuglog("Entering stage4...\n");
    global_chatsync_stage = 4;

    HEADER_ID_SEND = START_HEADER_ID + 1;
    HEADER_ID_SEND_CRC = HEADER_SLOT_CRC1;
    debuglog("HEADER_ID_SEND: 0x%08X\n", HEADER_ID_SEND);
    debuglog("HEADER_ID_SEND_CRC: 0x%08X\n", HEADER_ID_SEND_CRC);

	memset(buf,0,sizeof(buf));
  	buf_len=encode41_sess1pkt_cmd27(buf, sizeof(buf));
    do_proto_log(buf, buf_len, "send25");
    make_tcp_client_cmdpkt_wrap(buf, buf_len, "cmd27_finish");

    // PARAM send26

    global_chatsync_stage = 3;
    make_tcp_client_sess1_send_req();

    // PARAM recv26

    debuglog("Waiting for SYNC FINISH (0x27)\n");
    cmd = 0x27;
    while ( check_commands_array(cmd)==0 ){
        ret = make_tcp_client_sess1_recv_loop();
        if (ret < 0) { return ret; };
        show_memory(RECV_CHAT_COMMANDS, RECV_CHAT_COMMANDS_LEN, "RECV_CHAT_COMMANDS:");
    };
    debuglog("Got SYNC FINISH OK cmd\n");

    // PARAM send29

	memset(buf,0,sizeof(buf));
    buf_len = encode41_sess1pkt_error(buf, sizeof(buf));
    do_proto_log(buf, buf_len, "send29");
    make_tcp_client_cmdpkt_wrap(buf, buf_len, "_error_and_close");

    ret = make_tcp_client_sess1_recv_loop();
    if (ret < 0) { return ret; };

    // PARAM sendXXX

    // or should start with 0?
    //global_chatsync_stage = 5;
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


    debuglog_info("\nMSG SEND OK!\n");
    debuglog_info("FULL CHAT SESSION SYNC OK!\n");
    debuglog_info("CHAT SESSION SYNC-ed!\n");


    //INIT incoming_network_peer(1): networking :)
    //NETWORKED INIT NETWORKED
    //00-01: 06 00 00 00

    return 1;
};

