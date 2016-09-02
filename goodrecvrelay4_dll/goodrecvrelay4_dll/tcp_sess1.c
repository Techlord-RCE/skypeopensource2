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

// global aes blkseq key
extern int blkseq;

extern u8 CHAT_PEERS_REVERSED[0x100];


unsigned int make_tcp_client_sess1_pkt4(char *ip,unsigned short port){
    int ret;

	// if prev dat-file and session expired (24h) run new chatinit
    //chatrecv_newchatinit_pkts();
	// if prev session with this user not expired, run restore chat session
	//chatrecv_restorechat_pkts();

    ret = 0;
    if (make_tcp_client_get_chatinit()==0) {
        // no previous session found, start initing new chat session
        ret = chatrecv_newchatinit_pkts();
    } else {
        // previously stored session found!
        // just send pkts in restored session
    	ret = chatrecv_restorechat_pkts();
    };

	return ret;
};


int make_tcp_client_set_chatinit(char *tmpbuf, int cnt) {

    memcpy(REMOTE_CHAT_STRING,tmpbuf,cnt);

    //for new_msg2 and newblk4 forming

    memcpy(CHAT_STRING,tmpbuf,cnt);

    return 0;
};


//
// session get chatinit string
//
unsigned int make_tcp_client_get_chatinit() {
	int tmplen;
	unsigned int chatrnd;
	char tmpbuf[4096];
    int cnt;
	int ret;

    // load chatstring from a file

    memset(tmpbuf,0,sizeof(tmpbuf));
    //ret = load_chatstring_from_file(tmpbuf);
    ret = load_chatstring_from_db(tmpbuf);
    // some error
    if (ret < 0) { 
        return ret; 
    };
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


unsigned int make_tcp_client_sess1_send_A6_ack(int A6_sessid){
	int len;
	char *pkt;

	u8 buf1[0x1000];
	int buf1_len;
	u8 buf1header[0x10];
	int buf1header_len;

    int ack_debug = 0;

    memset(buf1,0,sizeof(buf1));
    buf1_len=encode41_sesspkt_A6_ack(buf1, sizeof(buf1), A6_sessid);

    if (ack_debug) show_memory(buf1, buf1_len, "sess_pkt_ack A6");
	 
	if (ack_debug) main_unpack(buf1, buf1_len);

	//aes encrypt block 1
	blkseq=blkseq+1;
	buf1_len=process_aes(buf1, buf1_len, 1, blkseq, 0);
	if (ack_debug) show_memory(buf1, buf1_len, "sess_pkt_ack");

	// first bytes correction
	// calculate for 4 and 5 byte fixing
	buf1header_len=first_bytes_correction(buf1header, sizeof(buf1header)-1, buf1, buf1_len);
	if (ack_debug) show_memory(buf1header, buf1header_len, "sess_pkt_ack_1header");

	// assembling pkt for sending
	pkt=(char *)malloc(0x1000);
	memset(pkt,0,0x1000);
	len=0;

	memcpy(pkt,buf1header,buf1header_len);
	len=len+buf1header_len;
	
	memcpy(pkt+len,buf1,buf1_len);
	len=len+buf1_len;
	

	// RC4 encrypt pkt
	if (ack_debug) show_memory(pkt, len, "Before RC4 encrypt");	
	RC4_crypt (pkt, len, &rc4_send, 0);
	if (ack_debug) show_memory(pkt, len, "After RC4 encrypt");	

	// display pkt
	if (ack_debug) show_memory(pkt, len, "Send pkt");

	// send pkt
	len=tcp_talk_send(pkt,len);
	if (len<=0) {
		debuglog("send err\n");
		return -1;
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

    int debug = 0;

	memset(buf1,0,sizeof(buf1));
  	buf1_len=encode41_sess1pkt_req(buf1, sizeof(buf1));
	if (debug) show_memory(buf1, buf1_len, "sess1pkt_req");

	main_unpack(buf1, buf1_len);

    do_proto_log(buf1, buf1_len, "send");

	//aes encrypt block 1
	blkseq=blkseq+1;
	buf1_len=process_aes(buf1, buf1_len, 1, blkseq, 0);

	// first bytes correction
	// calculate for 4 and 5 byte fixing
	buf1header_len=first_bytes_correction(buf1header, sizeof(buf1header)-1, buf1, buf1_len);
	if (debug) show_memory(buf1header, buf1header_len, "sess1pkt_req_header");


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


//
// recv loop
//
unsigned int make_tcp_client_sess1_recv_loop(){
	char result[0x2000];
	u8 recvbuf[0x2000];
	char header41[5];
	int pkt_block;
	int i;
    int ret;
	int len;
	int tmplen;
	int recvlen;
	int remote_blkseq;

	
	debuglog("\nEntering recv LOOP\n");

	// send pkt
	len=tcp_talk_recv2(result);
	if (len<=0) {
		debuglog("recv timeout\n");
		return -1;
	};
	
	// recv pkt
	show_memory(result, len, "Result");	

	// copy pkt
	recvlen=len;
	memcpy(recvbuf,result,recvlen);

	/////////////////////////////////
	// RC4 decrypt pkt
	/////////////////////////////////
	show_memory(recvbuf, recvlen, "Before RC4 decrypt");	
	RC4_crypt (recvbuf, recvlen, &rc4_recv, 0);
	show_memory(recvbuf, recvlen, "After RC4 decrypt");	

	if (len == 2) {
		debuglog ("\n");
		debuglog ("2 bytes of reply recv... possible this is 03 03 bytes...\n");
		debuglog ("\n");
		return -1;
	};

	ret = process_recv_data(recvbuf, recvlen);

	return ret;
};
