//
// restore chat session pkts (alternative send final)
//
#include <stdio.h>
#include <stdlib.h>

#include "short_types.h"

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

extern uint HEADER_SLOT_CRC1;
extern uint HEADER_SLOT_CRC2;
extern uint HEADER_SLOT_CRC3;

extern uint HEADER_ID_CMD27_CRC;
extern uint HEADER_ID_CMD27_ID;

extern int relay_connect_mode;

// end of init params


unsigned int do_alternative_restorechat_send_final_with_sync() {
	u8 buf[0x1000];
	int buf_len;
    unsigned int cmd;
    unsigned int tmp;
    int ret;

    //before: (new) PARAM recv26 from seqrecvsend (sproto) from 26.12.2015

    debuglog_info("Do alternative_restorechat_send_final_with_sync send...\n");   


    // some init

    /*
    // need for first our cmd13 to sync?
    ret = load_localheaders_from_db(&HEADER_ID_LOCAL_LAST, &tmp);
	if (ret == -1) {
		debuglog_err("Loading LASTSYNC data failed.\n");
		return -1;
	};
    */

    // end of init

    //
    // if got HEADER_ID_SEND in cmd10 msg sended ok.
    //




    // PARAM send26

    debuglog("Entering stage3...\n");
    global_chatsync_stage = 3;

    //in cmd13end we using START_HEADER_ID + 1
    START_HEADER_ID = HEADER_ID_REMOTE_LAST - 1;

	memset(buf,0,sizeof(buf));
    buf_len=encode41_sess1pkt_cmd13end(buf, sizeof(buf));
    do_proto_log(buf, buf_len, "new_send26");
    make_tcp_client_cmdpkt_wrap(buf, buf_len, "new_cmd13end");

    // PARAM send27

    debuglog("Entering stage4...\n");
    global_chatsync_stage = 4;

    // need last remote_header_id
    // B2 A0 60 05 (?)
    // i.e. remote_header_id from msg2 of newchatinit
    //HEADER_ID_SEND = 0x0560A0B2;

    // we know our lastsync before we added new msg for this actual send
    HEADER_ID_SEND = HEADER_ID_CMD27_ID;

	memset(buf,0,sizeof(buf));
    buf_len=encode41_sess1pkt_cmd10(buf, sizeof(buf));
    do_proto_log(buf, buf_len, "new_send27");
    make_tcp_client_cmdpkt_wrap(buf, buf_len, "new_cmd10");

    // PARAM send28

    global_chatsync_stage = 3;
    make_tcp_client_sess1_send_req();

    // PARAM recv30

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

    // PARAM send31

    debuglog("Entering stage5...\n");
    global_chatsync_stage = 5;

    //HEADER_ID_SEND = 0x0560A0B3;
    //HEADER_ID_SEND = HEADER_ID_SEND + 1;
    // get automatically from prev cmd13recv

	memset(buf,0,sizeof(buf));
    buf_len=encode41_sess1pkt_cmd10(buf, sizeof(buf));
    do_proto_log(buf, buf_len, "new_send31");
    make_tcp_client_cmdpkt_wrap(buf, buf_len, "new_cmd10_2");
 
    // PARAM send32

    global_chatsync_stage = 4;
    make_tcp_client_sess1_send_req();

    // PARAM recv35

    debuglog("Waiting for onHereIsExtraData (0x46)\n");
    cmd = 0x46;
    while ( check_commands_array(cmd)==0 ){
        ret = make_tcp_client_sess1_recv_loop();
        if (ret < 0) { return ret; };
        show_memory(RECV_CHAT_COMMANDS, RECV_CHAT_COMMANDS_LEN, "RECV_CHAT_COMMANDS:");
    };
    debuglog("Got onHereIsExtraData OK cmd\n");

    // PARAM send35

    global_chatsync_stage = 5;
    make_tcp_client_sess1_send_req();

    // PARAM recv36

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

    // PARAM send38

    debuglog("Entering stage6...\n");
    global_chatsync_stage = 6;

    HEADER_ID_SEND = START_HEADER_ID + 1;
    HEADER_ID_SEND_CRC = HEADER_SLOT_CRC1;
    debuglog("HEADER_ID_SEND: 0x%08X\n", HEADER_ID_SEND);
    debuglog("HEADER_ID_SEND_CRC: 0x%08X\n", HEADER_ID_SEND_CRC);

	memset(buf,0,sizeof(buf));
  	buf_len=encode41_sess1pkt_cmd27(buf, sizeof(buf));
    do_proto_log(buf, buf_len, "send38");
    make_tcp_client_cmdpkt_wrap(buf, buf_len, "new_cmd27_finish");

    // PARAM send39

    global_chatsync_stage = 6;
    make_tcp_client_sess1_send_req();

    //
    // session ok, waiting for error_and_close pkt now
    //

    // needed wait for sync close pkt
    debuglog("Waiting for close packet (and negative ret)\n");
    ret = 1;
    while (ret>0){
        ret = make_tcp_client_sess1_recv_loop();
    };
    if (ret != -20) {
        debuglog("Some error on getting close pkt.\n");
    }


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

    debuglog_info("\nMSG SEND OK!\n");
    debuglog_info("FULL CHAT SESSION SYNC OK!\n");
    debuglog_info("CHAT SESSION SYNC-ed!\n");

    /*
    debuglog("Waiting for ... (infinite)\n");
    while (1){
        ret = make_tcp_client_sess1_recv_loop();
        if (ret < 0) { return ret; };
    };
    */

    return 1;
};

