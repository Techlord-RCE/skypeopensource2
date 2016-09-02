/*  
*
* Direct TCP connect to skype client
* cmd 109 session
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
extern int process_aes_crypt(char *data, int datalen, int usekey, int blkseq, int need_xor);
extern int show_memory(char *mem, int len, char *text);
extern int get_packet_size(char *data,int len);
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

// global data

extern RC4_context rc4_send;
extern RC4_context rc4_recv;

extern u8 challenge_response[0x80];

extern u8 aes_key[0x20];
extern u32 remote_session_id;

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

extern uint HEADER_ID_REMOTE_LAST;
extern uint HEADER_ID_SEND;
extern uint HEADER_ID_SEND_CRC;

extern uint START_HEADER_ID;


extern uint NEWSESSION_FLAG;
extern uint NO_HEADERS_FLAG;

extern uint DEBUG_RC4;

extern uint global_chatsync_stage;

extern u8 RECV_CHAT_COMMANDS[0x100];
extern uint RECV_CHAT_COMMANDS_LEN;

extern uint GOT_CHAT_STRING_FROM_REMOTE;


// global aes blkseq key
extern int blkseq;

unsigned int check_commands_array(unsigned int cmd){
    unsigned int i=0;

	for (i=0;i<RECV_CHAT_COMMANDS_LEN;i++) {

        debuglog("i=%d, CMD=0x%08X\n",i, RECV_CHAT_COMMANDS[i]);

        if (RECV_CHAT_COMMANDS[i] == cmd){

			debuglog("I: 0x%08X\n",i);
			debuglog("CMD: 0x%08X\n",cmd);

			show_memory(RECV_CHAT_COMMANDS, RECV_CHAT_COMMANDS_LEN, "RECV_CHAT_COMMANDS (before):");
			memcpy(RECV_CHAT_COMMANDS, RECV_CHAT_COMMANDS+i,RECV_CHAT_COMMANDS_LEN-i);
			show_memory(RECV_CHAT_COMMANDS, RECV_CHAT_COMMANDS_LEN, "RECV_CHAT_COMMANDS (after):");
            
			// zero-ing rest of buffer
            RECV_CHAT_COMMANDS_LEN = RECV_CHAT_COMMANDS_LEN - i;
            memset(RECV_CHAT_COMMANDS+RECV_CHAT_COMMANDS_LEN, 0x00, 0x100-RECV_CHAT_COMMANDS_LEN);

			show_memory(RECV_CHAT_COMMANDS, RECV_CHAT_COMMANDS_LEN, "RECV_CHAT_COMMANDS (after zeroing):");

            return 1;
        };
	};

    return 0;
};


unsigned int make_tcp_client_sess1_pkt4(){
	int ret;
    int chatinit;

    chatinit = do_get_chatinit();
    if (chatinit < 0) { return -1; };

    // no previous session found in file, need to check remote side
    if (chatinit==0) {

        ret = send_newchatinit_pkts();

        //
        // for later examine
        //

        /*
        //ret = make_tcp_client_sess1_recv_loop();
        //if (ret < 0) { return ret; };

		debuglog_info("GOT_CHAT_STRING_FROM_REMOTE = %d\n",GOT_CHAT_STRING_FROM_REMOTE);

        if (GOT_CHAT_STRING_FROM_REMOTE==0) {
            debuglog_info("No cmd0D received.\n");
            // no prev session found on remote, start initing new chat session
            ret = send_newchatinit_pkts();
        } else {
            // prev session found on remote, do send in restore session
            debuglog_info("Hola! cmd0D received! Right after 7D and 7A!\n");

            //save_good_chatstring();
            save_chatstrin_to_db();

            do_sync_session_close();

            // close session and do reconnect?
            return -200;            
			
			// for investigate later
			// hmmm need just save and do restore session?
        	//ret = send_chatremote_pkts();

			ret = send_chatrestore_pkts();
			
			// not tested, not reversed
			//return -10;
        };
        */


    } else {
        // previously stored session found!
        // just send pkts in restored session
    	ret = send_chatrestore_pkts();
    };

	/*
	make_tcp_client_sess1_recv_loop();
	make_tcp_client_sess1_recv_loop();
	make_tcp_client_sess1_recv_loop();
	*/

	return ret;
};




//
// session prepare, make semi-random chat_string for it
//
unsigned int make_tcp_client_prepare_chatinit(){
	int tmplen;
	unsigned int chatrnd;


    // for tests
    // bc5ffd9299007750
	//tmplen=strlen(CHAT_STRING)-16;
	//memcpy(CHAT_STRING+tmplen,"bc5ffd9299007750",16);


    //
    // sendproto1/sendproto2
    //"#notnowagainplease/$themagicforyou;8c497ce72cbd1e4e"
    //
    tmplen=strlen(CHAT_STRING)-16;
    memcpy(CHAT_STRING+tmplen,"8c497ce72cbd1e4e",16);
    //


    //
    // not need generate for test
    // but need in production
    //

    if (0) {
    	tmplen=strlen(CHAT_STRING)-4;

    	chatrnd=(rand() % 0x9);
    	CHAT_STRING[tmplen]=CHAT_STRING[tmplen]+chatrnd;
    	tmplen++;
    	debuglog("chatrnd=%d\n",chatrnd);

    	chatrnd=(rand() % 0x9);
    	CHAT_STRING[tmplen]=CHAT_STRING[tmplen]+chatrnd;
    	tmplen++;
    	debuglog("chatrnd=%d\n",chatrnd);

    	chatrnd=(rand() % 0x9);
    	CHAT_STRING[tmplen]=CHAT_STRING[tmplen]+chatrnd;
    	tmplen++;
    	debuglog("chatrnd=%d\n",chatrnd);

    	chatrnd=(rand() % 0x9);
    	CHAT_STRING[tmplen]=CHAT_STRING[tmplen]+chatrnd;
    	tmplen++;
    	debuglog("chatrnd=%d\n",chatrnd);
    };

	debuglog("CHAT ID:%s\n",CHAT_STRING);

	return 0;
};


//
// session get chatinit string
//
unsigned int do_get_chatinit() {
	int tmplen;
	unsigned int chatrnd;
	char tmpbuf[4096];
    int cnt;
    int ret;

	//u8 CHAR_RND_ID[0x100]="bc5ffd9299000000";
    //CHAR_RND_ID = "bc5ffd9299003276";
	//tmplen=strlen(CHAT_STRING)-16;
	//memcpy(CHAT_STRING+tmplen,"bc5ffd9299003276",16);

    /*
	tmplen=strlen(CHAT_STRING)-16;
	memcpy(CHAT_STRING+tmplen,"bc5ffd9299007786",16);
	debuglog("CHAT ID:%s\n",CHAT_STRING);
    */

    // load chatstring from a file

    memset(tmpbuf,0,sizeof(tmpbuf));
    //cnt = load_chatstring_from_file(tmpbuf);
    ret = load_chatstring_from_db(tmpbuf);
    // some error
    if (ret < 0) { return ret; };
    if (ret > 0) {
        // prev session found
        cnt = strlen(CHAT_STRING);
    	memcpy(CHAT_STRING,tmpbuf,cnt);
    } else {
        // needed init new chat session
    	return 0;
    };

	return 1;
};


unsigned int make_tcp_client_cmdpkt_wrap(u8 *buf1, int buf1_len, char *str) {
	int len;
	char *pkt;

	u8 buf1header[0x10];
	int buf1header_len;

    int debug = 0;


	debuglog("::: encode new logic packet for send :::\n\n\n");
	show_memory(buf1, buf1_len, str);

	main_unpack(buf1, buf1_len);

	//aes encrypt block 1
	blkseq=blkseq+1;
	buf1_len=process_aes(buf1, buf1_len, 1, blkseq, 0);


	// first bytes correction
	// calculate for 4 and 5 byte fixing
	buf1header_len=first_bytes_correction(buf1header, sizeof(buf1header)-1, buf1, buf1_len);
    debuglog("Calculated header ok\n");
	if (debug) show_memory(buf1header, buf1header_len, str);


	// assembling pkt for sending
	pkt=(char *)malloc(0x1000);
	memset(pkt,0,0x1000);
	len=0;

	memcpy(pkt,buf1header,buf1header_len);
	len=len+buf1header_len;
	
	memcpy(pkt+len,buf1,buf1_len);
	len=len+buf1_len;
	

	// RC4 encrypt pkt
	if (debug) show_memory(pkt, len, "Before RC4 encrypt");	
	RC4_crypt (pkt, len, &rc4_send, 0);
	if (debug) show_memory(pkt, len, "After RC4 encrypt");	

	// display pkt
	if (debug) show_memory(pkt, len, "Send pkt");

	// send pkt
	len=tcp_talk_send(pkt,len);
	if (len<=0) {
		debuglog("send err\n");
		return -1;
	};

	return 0;
};


unsigned int make_tcp_client_sess1_send_A6_ack(int A6_sessid){
	int len;
	char *pkt;

	u8 buf1[0x1000];
	int buf1_len;
	u8 buf1header[0x10];
	int buf1header_len;

	
	//hmmm?
	//blkseq=blkseq+1;

    memset(buf1,0,sizeof(buf1));
    buf1_len=encode41_sesspkt_A6_ack(buf1, sizeof(buf1), A6_sessid);
    show_memory(buf1, buf1_len, "sess_pkt_ack A6");
	 
	main_unpack(buf1, buf1_len);

	//aes encrypt block 1
	blkseq=blkseq+1;
	buf1_len=process_aes(buf1, buf1_len, 1, blkseq, 0);
	show_memory(buf1, buf1_len, "sess_pkt_ack");


	// first bytes correction
	// calculate for 4 and 5 byte fixing
	buf1header_len=first_bytes_correction(buf1header, sizeof(buf1header)-1, buf1, buf1_len);
	show_memory(buf1header, buf1header_len, "sess_pkt_ack_1header");


	// assembling pkt for sending
	pkt=(char *)malloc(0x1000);
	memset(pkt,0,0x1000);
	len=0;

	memcpy(pkt,buf1header,buf1header_len);
	len=len+buf1header_len;
	
	memcpy(pkt+len,buf1,buf1_len);
	len=len+buf1_len;
	

	// RC4 encrypt pkt
	show_memory(pkt, len, "Before RC4 encrypt");	
	RC4_crypt (pkt, len, &rc4_send, 0);
	show_memory(pkt, len, "After RC4 encrypt");	

	// display pkt
	show_memory(pkt, len, "Send pkt");

	// send pkt
	len=tcp_talk_send(pkt,len);
	if (len<=0) {
		debuglog("send err\n");
		return len;
	};


	return 0;
};


unsigned int make_tcp_client_sess1_send_5E(unsigned int data_5E_bytes){
	int len;
	char *pkt;

	u8 buf1[0x1000];
	int buf1_len;
	u8 buf1header[0x10];
	int buf1header_len;


	memset(buf1,0,sizeof(buf1));
  	buf1_len=encode41_sess1pkt_5E(buf1, sizeof(buf1), data_5E_bytes);
	show_memory(buf1, buf1_len, "sess1pkt_5E");

	main_unpack(buf1, buf1_len);


	//aes encrypt block 1
	blkseq=blkseq+1;
	buf1_len=process_aes(buf1, buf1_len, 1, blkseq, 0);


	// first bytes correction
	// calculate for 4 and 5 byte fixing
	buf1header_len=first_bytes_correction(buf1header, sizeof(buf1header)-1, buf1, buf1_len);
	show_memory(buf1header, buf1header_len, "sess1pkt_5E_header");


	// assembling pkt for sending
	pkt=(char *)malloc(0x1000);
	memset(pkt,0,0x1000);
	len=0;

	memcpy(pkt,buf1header,buf1header_len);
	len=len+buf1header_len;
	
	memcpy(pkt+len,buf1,buf1_len);
	len=len+buf1_len;
	

	// RC4 encrypt pkt
	show_memory(pkt, len, "Before RC4 encrypt");	
	RC4_crypt (pkt, len, &rc4_send, 0);
	show_memory(pkt, len, "After RC4 encrypt");	

	// display pkt
	show_memory(pkt, len, "Send pkt");

	// send pkt
	len=tcp_talk_send(pkt,len);
	if (len<=0) {
		debuglog("send err\n");
		return len;
	};


	return 0;
};


unsigned int make_tcp_client_sess1_send_7D(char *ip,unsigned short port){
	int len;
	char *pkt;

	u8 buf1[0x1000];
	int buf1_len;
	u8 buf1header[0x10];
	int buf1header_len;



	memset(buf1,0,sizeof(buf1));
  	buf1_len=encode41_sess1pkt_7D(buf1, sizeof(buf1));
	show_memory(buf1, buf1_len, "sess1pkt_7D");

	main_unpack(buf1, buf1_len);


	//aes encrypt block 1
	blkseq=blkseq+1;
	buf1_len=process_aes(buf1, buf1_len, 1, blkseq, 0);


	// first bytes correction
	// calculate for 4 and 5 byte fixing
	buf1header_len=first_bytes_correction(buf1header, sizeof(buf1header)-1, buf1, buf1_len);
	show_memory(buf1header, buf1header_len, "sess1pkt_7D_header");


	// assembling pkt for sending
	pkt=(char *)malloc(0x1000);
	memset(pkt,0,0x1000);
	len=0;

	memcpy(pkt,buf1header,buf1header_len);
	len=len+buf1header_len;
	
	memcpy(pkt+len,buf1,buf1_len);
	len=len+buf1_len;
	

	// RC4 encrypt pkt
	show_memory(pkt, len, "Before RC4 encrypt");	
	RC4_crypt (pkt, len, &rc4_send, 0);
	show_memory(pkt, len, "After RC4 encrypt");	

	// display pkt
	show_memory(pkt, len, "Send pkt");

	// send pkt
	len=tcp_talk_send(pkt,len);
	if (len<=0) {
		debuglog("send err\n");
		return len;
	};


	return 0;
};


unsigned int make_tcp_client_sess1_send_7A(char *ip,unsigned short port){
	int len;
	char *pkt;

	u8 buf1[0x1000];
	int buf1_len;
	u8 buf1header[0x10];
	int buf1header_len;



	memset(buf1,0,sizeof(buf1));
  	buf1_len=encode41_sess1pkt_7A(buf1, sizeof(buf1));
	show_memory(buf1, buf1_len, "sess1pkt_7A");

	main_unpack(buf1, buf1_len);

	//aes encrypt block 1
	blkseq=blkseq+1;
	buf1_len=process_aes(buf1, buf1_len, 1, blkseq, 0);


	// first bytes correction
	// calculate for 4 and 5 byte fixing
	buf1header_len=first_bytes_correction(buf1header, sizeof(buf1header)-1, buf1, buf1_len);
	show_memory(buf1header, buf1header_len, "sess1pkt_7A_header");

	// assembling pkt for sending
	pkt=(char *)malloc(0x1000);
	memset(pkt,0,0x1000);
	len=0;

	memcpy(pkt,buf1header,buf1header_len);
	len=len+buf1header_len;
	
	memcpy(pkt+len,buf1,buf1_len);
	len=len+buf1_len;
	

	// RC4 encrypt pkt
	show_memory(pkt, len, "Before RC4 encrypt");	
	RC4_crypt (pkt, len, &rc4_send, 0);
	show_memory(pkt, len, "After RC4 encrypt");	

	// display pkt
	show_memory(pkt, len, "Send pkt");

	// send pkt
	len=tcp_talk_send(pkt,len);
	if (len<=0) {
		debuglog("send err\n");
		return len;
	};


	return 0;
};


unsigned int make_tcp_client_sess1_send_7B(char *ip,unsigned short port){
	int len;
	char *pkt;

	u8 buf1[0x1000];
	int buf1_len;
	u8 buf1header[0x10];
	int buf1header_len;



	memset(buf1,0,sizeof(buf1));
  	buf1_len=encode41_sess1pkt_7B(buf1, sizeof(buf1));
	show_memory(buf1, buf1_len, "sess1pkt_7B");

	main_unpack(buf1, buf1_len);

	//aes encrypt block 1
	blkseq=blkseq+1;
	buf1_len=process_aes(buf1, buf1_len, 1, blkseq, 0);


	// first bytes correction
	// calculate for 4 and 5 byte fixing
	buf1header_len=first_bytes_correction(buf1header, sizeof(buf1header)-1, buf1, buf1_len);
	show_memory(buf1header, buf1header_len, "sess1pkt_7B_header");

	// assembling pkt for sending
	pkt=(char *)malloc(0x1000);
	memset(pkt,0,0x1000);
	len=0;

	memcpy(pkt,buf1header,buf1header_len);
	len=len+buf1header_len;
	
	memcpy(pkt+len,buf1,buf1_len);
	len=len+buf1_len;
	

	// RC4 encrypt pkt
	show_memory(pkt, len, "Before RC4 encrypt");	
	RC4_crypt (pkt, len, &rc4_send, 0);
	show_memory(pkt, len, "After RC4 encrypt");	

	// display pkt
	show_memory(pkt, len, "Send pkt");

	// send pkt
	len=tcp_talk_send(pkt,len);
	if (len<=0) {
		debuglog("send err\n");
		return len;
	};


	return 0;
};


unsigned int make_tcp_client_sess1_send_58(char *ip,unsigned short port) {
	int len;
	char *pkt;

	u8 buf1[0x1000];
	int buf1_len;
	u8 buf1header[0x10];
	int buf1header_len;



	memset(buf1,0,sizeof(buf1));
  	buf1_len=encode41_sess1pkt_58(buf1, sizeof(buf1));
	show_memory(buf1, buf1_len, "sess1pkt_58");

	main_unpack(buf1, buf1_len);

	//aes encrypt block 1
	blkseq=blkseq+1;
	buf1_len=process_aes(buf1, buf1_len, 1, blkseq, 0);


	// first bytes correction
	// calculate for 4 and 5 byte fixing
	buf1header_len=first_bytes_correction(buf1header, sizeof(buf1header)-1, buf1, buf1_len);
	show_memory(buf1header, buf1header_len, "sess1pkt_58_header");

	// assembling pkt for sending
	pkt=(char *)malloc(0x1000);
	memset(pkt,0,0x1000);
	len=0;

	memcpy(pkt,buf1header,buf1header_len);
	len=len+buf1header_len;
	
	memcpy(pkt+len,buf1,buf1_len);
	len=len+buf1_len;
	

	// RC4 encrypt pkt
	show_memory(pkt, len, "Before RC4 encrypt");	
	RC4_crypt (pkt, len, &rc4_send, 0);
	show_memory(pkt, len, "After RC4 encrypt");	

	// display pkt
	show_memory(pkt, len, "Send pkt");

	// send pkt
	len=tcp_talk_send(pkt,len);
	if (len<=0) {
		debuglog("send err\n");
		return len;
	};


	return 0;
};


unsigned int make_tcp_client_sess1_send_53(char *ip,unsigned short port){
	int len;
	char *pkt;

	u8 buf1[0x1000];
	int buf1_len;
	u8 buf1header[0x10];
	int buf1header_len;



	memset(buf1,0,sizeof(buf1));
  	buf1_len=encode41_sess1pkt_53(buf1, sizeof(buf1));
	show_memory(buf1, buf1_len, "sess1pkt_53");

	main_unpack(buf1, buf1_len);

	//aes encrypt block 1
	blkseq=blkseq+1;
	buf1_len=process_aes(buf1, buf1_len, 1, blkseq, 0);


	// first bytes correction
	// calculate for 4 and 5 byte fixing
	buf1header_len=first_bytes_correction(buf1header, sizeof(buf1header)-1, buf1, buf1_len);
	show_memory(buf1header, buf1header_len, "sess1pkt_53_header");


	// assembling pkt for sending
	pkt=(char *)malloc(0x1000);
	memset(pkt,0,0x1000);
	len=0;

	memcpy(pkt,buf1header,buf1header_len);
	len=len+buf1header_len;
	
	memcpy(pkt+len,buf1,buf1_len);
	len=len+buf1_len;
	

	// RC4 encrypt pkt
	if (DEBUG_RC4) { show_memory(pkt, len, "Before RC4 encrypt"); };
	RC4_crypt (pkt, len, &rc4_send, 0);
	if (DEBUG_RC4) { show_memory(pkt, len, "After RC4 encrypt");	};

	// display pkt
	show_memory(pkt, len, "Send pkt");

	// send pkt
	len=tcp_talk_send(pkt,len);
	if (len<=0) {
		debuglog("send err\n");
		return len;
	};


	return 0;
};


unsigned int make_tcp_client_sess1_send_req(char *ip,unsigned short port){
	int len;
	char *pkt;

	u8 buf1[0x1000];
	int buf1_len;
	u8 buf1header[0x10];
	int buf1header_len;



	memset(buf1,0,sizeof(buf1));
  	buf1_len=encode41_sess1pkt_req(buf1, sizeof(buf1));
	show_memory(buf1, buf1_len, "sess1pkt_req");

	main_unpack(buf1, buf1_len);

    do_proto_log(buf1, buf1_len, "send");

	//aes encrypt block 1
	blkseq=blkseq+1;
	buf1_len=process_aes(buf1, buf1_len, 1, blkseq, 0);


	// first bytes correction
	// calculate for 4 and 5 byte fixing
	buf1header_len=first_bytes_correction(buf1header, sizeof(buf1header)-1, buf1, buf1_len);
	show_memory(buf1header, buf1header_len, "sess1pkt_req_header");


	// assembling pkt for sending
	pkt=(char *)malloc(0x1000);
	memset(pkt,0,0x1000);
	len=0;

	memcpy(pkt,buf1header,buf1header_len);
	len=len+buf1header_len;
	
	memcpy(pkt+len,buf1,buf1_len);
	len=len+buf1_len;
	

	// RC4 encrypt pkt
	show_memory(pkt, len, "Before RC4 encrypt");	
	RC4_crypt (pkt, len, &rc4_send, 0);
	show_memory(pkt, len, "After RC4 encrypt");	

	// display pkt
	show_memory(pkt, len, "Send pkt");

	// send pkt
	len=tcp_talk_send(pkt,len);
	if (len<=0) {
		debuglog("send err\n");
		return len;
	};

	return 0;
};



unsigned int make_tcp_client_sess1_send_sendheaders() {
	int len;
	char *pkt;

	u8 buf1[0x1000];
	int buf1_len;
	u8 buf1header[0x10];
	int buf1header_len;


	debuglog("\n\n\n");

	memset(buf1,0,sizeof(buf1));
  	buf1_len=encode41_sess1pkt_cmd13one(buf1, sizeof(buf1));
	show_memory(buf1, buf1_len, "sess1pkt_cmd13one");

	main_unpack(buf1, buf1_len);

	//aes encrypt block 1
	blkseq=blkseq+1;
	buf1_len=process_aes(buf1, buf1_len, 1, blkseq, 0);


	// first bytes correction
	// calculate for 4 and 5 byte fixing
	buf1header_len=first_bytes_correction(buf1header, sizeof(buf1header)-1, buf1, buf1_len);
	show_memory(buf1header, buf1header_len, "sess1pkt_cmd13one_header");


	// assembling pkt for sending
	pkt=(char *)malloc(0x1000);
	memset(pkt,0,0x1000);
	len=0;

	memcpy(pkt,buf1header,buf1header_len);
	len=len+buf1header_len;
	
	memcpy(pkt+len,buf1,buf1_len);
	len=len+buf1_len;
	

	// RC4 encrypt pkt
	show_memory(pkt, len, "Before RC4 encrypt");	
	RC4_crypt (pkt, len, &rc4_send, 0);
	show_memory(pkt, len, "After RC4 encrypt");	

	// display pkt
	show_memory(pkt, len, "Send pkt");

	// send pkt
	len=tcp_talk_send(pkt,len);
	if (len<=0) {
		debuglog("send err\n");
		return len;
	};

	return 0;
};


//
// recv loop
//
unsigned int make_tcp_client_sess1_recv_loop(){
	char result[0x20000];
	u8 recvbuf[0x20000];
	char header41[5];
	int pkt_block;
	int i;
	int len;
	int tmplen;
	int recvlen;
	int remote_blkseq;
    int ret;
	
	debuglog("\nEntering recv LOOP\n");

	// send pkt
	len=tcp_talk_recv2(result);
	if (len<=0) {
		debuglog("recv timeout\n");
		return -1;
	};
	
	// recv pkt
	show_memory(result, len, "Result");	

	if (len == 2) {
		debuglog ("2 bytes of reply recv... possible this is 03 03 bytes...\n");
		return -1;
	};

	// copy pkt
	recvlen=len;
	memcpy(recvbuf,result,recvlen);


	/////////////////////////////////
	// RC4 decrypt pkt
	/////////////////////////////////
	show_memory(recvbuf, recvlen, "Before RC4 decrypt");	
	RC4_crypt (recvbuf, recvlen, &rc4_recv, 0);
	show_memory(recvbuf, recvlen, "After RC4 decrypt");	

	ret = process_recv_data(recvbuf, recvlen);

	return ret;
};

