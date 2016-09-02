/*  
*
* Direct TCP connect to skype client
* cmd 109 session
*
*/

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
extern uint NEWSESSION_FLAG;
extern uint NO_HEADERS_FLAG;

extern uint DEBUG_RC4;

extern uint global_chatsync_stage;

extern uint RECV_CHAT_COMMAND;

// global aes blkseq key
extern int blkseq;



unsigned int make_tcp_client_prepare_newblk_chatsign() {
	char result[0x1000];
	u8 recvbuf[0x1000];
	char header41[5];
	int i,j;
	int len;
	int tmplen;
	int recvlen;
	int blkseq;
	int remote_blkseq;
	char *pkt;

	u8 buf1[0x1000];
	int buf1_len;
	u8 buf1header[0x10];
	int buf1header_len;

	u8 buf2[0x1000];
	int buf2_len;
	u8 buf2header[0x10];
	int buf2header_len;
	
	u8 buf3[0x1000];
	int buf3_len;
	u8 buf3header[0x10];
	int buf3header_len;
	
	u8 buf4[0x1000];
	int buf4_len;
	u8 buf4header[0x10];
	int buf4header_len;
	

	u8 buf_newblk1[0x1000];
	int buf_newblk1_len;


	///////////////////////////////
	// second 41
	///////////////////////////////


	memset(NEWBLK,0,sizeof(NEWBLK));
	NEWBLK_LEN=0;

	NEWBLK[0]=0x6A;
    NEWBLK_LEN++;

	/////////////////////////////
	// SHA1 digest 0
	/////////////////////////////
	// for make digest at the _start_ of newbkl
	// crypted credentials(0x100) + chatid(0x24)
	if (1) {
		char *buf;
		char *outbuf;
		int tlen;

		buf=malloc(0x1000);
		outbuf=malloc(0x1000);

		memset(buf,0,0x1000);
		memset(outbuf,0,0x1000);

		// credentials
		memcpy(buf,CREDENTIALS, CREDENTIALS_LEN);

		// chatid 
		memcpy(buf+CREDENTIALS_LEN,CHAT_STRING,strlen(CHAT_STRING));
		tlen=CREDENTIALS_LEN+strlen(CHAT_STRING);

		// show data for hashing
		show_memory(buf, tlen, "CHATID input");

		// making sha1 hash
		_get_sha1_data(buf,tlen,outbuf,1);

		// show 
		show_memory(outbuf, 0x14, "CHATID(hash) OUTPUT");

		// copy sha1 to new blk, at start+1
		memcpy(NEWBLK+NEWBLK_LEN,outbuf,0x14);
    	NEWBLK_LEN+=0x14;

	};




	
	//////////////////////////////////////////////////
	// modify chatid in newblk , in aes data
	//////////////////////////////////////////////////
	memcpy(NEWBLK+NEWBLK_LEN,CHAT_STRING,strlen(CHAT_STRING));
	NEWBLK_LEN+=strlen(CHAT_STRING);

    show_memory_with_ascii(NEWBLK, NEWBLK_LEN, "NEWBLK1");

	memset(buf_newblk1,0,sizeof(buf_newblk1));
  	buf_newblk1_len=encode41_newblk1(buf_newblk1, sizeof(buf_newblk1));
	show_memory(buf_newblk1, buf_newblk1_len, "buf_newblk1");

	debuglog("Check newblk1 41 packing:\n");
	main_unpack(buf_newblk1, buf_newblk1_len);

	do_proto_log(buf_newblk1, buf_newblk1_len, "newblk1_decode");

	tmplen=buf_newblk1_len;
	if(1){
		int tlen_ost;
		int tlen_need;
		int tlen_first;
		int tlen_second;

		tlen_ost=0x80-NEWBLK_LEN-0x15;
		tlen_need=buf_newblk1_len;

		if (tlen_ost < tlen_need){
			tlen_first=tlen_ost;
			tlen_second=tlen_need-tlen_first;
			tmplen=tlen_first;
		};
	
	};


	// middle of newblk .. some 41 data..
    memcpy(NEWBLK+NEWBLK_LEN,buf_newblk1,tmplen);
	NEWBLK_LEN+=tmplen;


	if (NEWBLK_LEN+0x15 != 0x80) {
			show_memory(NEWBLK,0x80,"newblk:");
			debuglog("NEWBLK LEN encode error, LEN=0x%08X\n",NEWBLK_LEN+0x15);
			return -1;
	};

	NEWBLK[0x7f]=0xBC;

	/////////////////////////////
	// SHA1 digest 1
	/////////////////////////////
	// for make digest at the end of newblk
	// data under crypto(0x80) + cleartext data after(0x12)
	if (1) {
		char *buf;
		char *outbuf;
		u32 tlen;


		NEWBLK_LEN=0x80;

		if ( tmplen!= buf_newblk1_len ){
			// aes41
			tlen=buf_newblk1_len-tmplen;
			memcpy(NEWBLK+NEWBLK_LEN,buf_newblk1+tmplen,tlen);
			NEWBLK_LEN+=tlen;
		};



		/*
	    memcpy(NEWBLK+NEWBLK_LEN,"\x01",1);
		NEWBLK_LEN++;

		tlen=strlen(REMOTE_NAME)+1;
	    memcpy(NEWBLK+NEWBLK_LEN,REMOTE_NAME,tlen);
		NEWBLK_LEN+=tlen;

	    memcpy(NEWBLK+NEWBLK_LEN,"\x00\x0A\xAA\xEE\xF5\x46\x00\x0B\x01", 9);
	    NEWBLK_LEN+=9;

		*/

		buf=malloc(0x1000);
		outbuf=malloc(0x1000);

		memset(buf,0,0x1000);
		memset(outbuf,0,0x1000);

		// first char not count 
		// last 0x14 + BC is sha1 hash
		tlen=0x80-0x14-1-1;
		memcpy(buf,NEWBLK+1,tlen);
		memcpy(buf+tlen,NEWBLK+0x80,NEWBLK_LEN-0x80);
		tlen=tlen+NEWBLK_LEN-0x80;

		// show data for hashing
		show_memory(buf, tlen, "NEWBLK input");

		// making sha1 hash
		_get_sha1_data(buf,tlen,outbuf,1);


		// show 
		show_memory(outbuf, 0x14, "NEWBLK(hash) OUTPUT");

		// copy sha1 to new blk, at end, before BC
		memcpy(NEWBLK+0x80-0x14-1,outbuf,0x14);

	};


	show_memory(NEWBLK, NEWBLK_LEN, "NEWBLK new OUTPUT");

	
	///////////////////////
	//RSA sign
	///////////////////////
	//for sign newblk with our(xoteg) private key
	if (1) {
		char *buf;
		char *outbuf;


		buf=malloc(0x1000);
		outbuf=malloc(0x1000);

		memset(buf,0,0x1000);
		memset(outbuf,0,0x1000);


		//copy challenge template
		memcpy(buf,NEWBLK,0x80);
		
		//print newblk data
		//before RSA sign-ing
		show_memory(buf, 0x80, "newblk RSA SIGN input");

		//make rsa sign
		_get_sign_data(buf, 0x80, outbuf);

		////copy rsa sign to challenge_response buffer
		////for send this response in next pkt
		memcpy(NEWBLK,outbuf,0x80);

		//print rsa signed newblk data
		show_memory(outbuf, 0x80, "newblk RSA SIGN output");

	};
	
    return 0;
};


//
// newblk2 with headers prepare
//
unsigned int make_tcp_client_prepare_newblk_headsign() {
	char result[0x1000];
	u8 recvbuf[0x1000];
	char header41[0x100];
	int i,j;
	int len;
	int tmplen;
	int recvlen;
	int blkseq;
	int remote_blkseq;
	char *pkt;

	u8 buf1[0x1000];
	int buf1_len;
	u8 buf1header[0x10];
	int buf1header_len;

	u8 buf2[0x1000];
	int buf2_len;
	u8 buf2header[0x10];
	int buf2header_len;

	u8 buf3[0x1000];
	int buf3_len;
	u8 buf3header[0x10];
	int buf3header_len;

	u8 buf4[0x1000];
	int buf4_len;
	u8 buf4header[0x10];
	int buf4header_len;

	u8 buf5[0x1000];
	int buf5_len;
	u8 buf5header[0x10];
	int buf5header_len;

	u8 buf6[0x1000];
	int buf6_len;
	u8 buf6header[0x10];
	int buf6header_len;

	u8 buf7[0x1000];
	int buf7_len;
	u8 buf7header[0x10];
	int buf7header_len;

	u8 buf8[0x1000];
	int buf8_len;
	u8 buf8header[0x10];
	int buf8header_len;

	u8 buf9[0x1000];
	int buf9_len;
	u8 buf9header[0x10];
	int buf9header_len;

	u8 buf_newblk2[0x1000];
	int buf_newblk2_len;



	///////////////////////////////
	// fouth block4 41
	///////////////////////////////


	//////////////////////////////////////////////////
	// modify credentials, in aes data
	//////////////////////////////////////////////////
	//memcpy(aes_41data4+0xc5,aes_41data4_fix,0x100);


	memset(NEWBLK,0,sizeof(NEWBLK));
	NEWBLK_LEN=0;

	NEWBLK[0]=0x6A;
    NEWBLK_LEN++;


	/////////////////////////////
	// SHA1 digest 0
	/////////////////////////////
	// for make digest at the _start_ of newbkl
	// crypted credentials(0x100) + chatid(0x24)
	if (1) {
		char *buf;
		char *outbuf;
		int tlen;

		buf=malloc(0x1000);
		outbuf=malloc(0x1000);

		memset(buf,0,0x1000);
		memset(outbuf,0,0x1000);

		// credentials
		memcpy(buf,CREDENTIALS,CREDENTIALS_LEN);

		// + chatid 
		//memcpy(buf+4+0x100,"#xoteg_iam/$xot_iam;4fef7b015cb20ad0",0x24);
		memcpy(buf+CREDENTIALS_LEN,CHAT_STRING,strlen(CHAT_STRING));
		tlen=CREDENTIALS_LEN+strlen(CHAT_STRING);

		// show data for hashing
		show_memory(buf, tlen, "CHATID 2 input");

		// making sha1 hash
		_get_sha1_data(buf,tlen,outbuf,1);

		// show 
		show_memory(outbuf, 0x14, "CHATID(hash) 2 OUTPUT");

		// copy sha1 to new blk, at start+1
		memcpy(NEWBLK+1,outbuf,0x14);
		NEWBLK_LEN+=0x14;

	};




	
	//////////////////////////////////////////////////
	// modify chatid in newblk , in aes data
	//////////////////////////////////////////////////
	//memcpy(aes_41data4_newblk+0x15,"#xoteg_iam/$xot_iam;4fef7b015cb20ad0",0x24);
	//memcpy(aes_41data4_newblk+0x15,CHAT_STRING,0x24);

	memcpy(NEWBLK+NEWBLK_LEN,CHAT_STRING,strlen(CHAT_STRING));
	NEWBLK_LEN+=strlen(CHAT_STRING);

    show_memory_with_ascii(NEWBLK, NEWBLK_LEN, "NEWBLK2");

	memset(buf_newblk2,0,sizeof(buf_newblk2));
  	buf_newblk2_len=encode41_newblk2(buf_newblk2, sizeof(buf_newblk2));
	show_memory(buf_newblk2, buf_newblk2_len, "buf_newblk2");

	debuglog("Check newblk2 41 packing:\n");
	main_unpack(buf_newblk2, buf_newblk2_len);

	do_proto_log(buf_newblk2, buf_newblk2_len, "newblk2_decode");

	tmplen=buf_newblk2_len;
	if(1){
		int tlen_ost;
		int tlen_need;
		int tlen_first;
		int tlen_second;

		tlen_ost=0x80-NEWBLK_LEN-0x15;
		tlen_need=buf_newblk2_len;

		if (tlen_ost < tlen_need){
			tlen_first=tlen_ost;
			tlen_second=tlen_need-tlen_first;
			tmplen=tlen_first;
		};
	
	};


	// middle of newblk .. some 41 data..
    memcpy(NEWBLK+NEWBLK_LEN,buf_newblk2,tmplen);
	NEWBLK_LEN+=tmplen;


	if (NEWBLK_LEN+0x15 != 0x80) {
			show_memory(NEWBLK,0x80,"newblk:");
			debuglog("NEWBLK2 LEN encode error, LEN=0x%08X\n",NEWBLK_LEN+0x15);
			return -1;
	};

	NEWBLK[0x7f]=0xBC;

	

	/////////////////////////////
	// SHA1 digest 1
	/////////////////////////////
	// for make digest at the end of newblk
	// data under crypto(0x80) + cleartext data after(0x0c)
	if (1) {
		char *buf;
		char *outbuf;
		u32 tlen;

		NEWBLK_LEN=0x80;

		if ( tmplen!= buf_newblk2_len ){
			// aes41
			tlen=buf_newblk2_len-tmplen;
			memcpy(NEWBLK+NEWBLK_LEN,buf_newblk2+tmplen,tlen);
			NEWBLK_LEN+=tlen;
		};


		/*
		memcpy(NEWBLK+NEWBLK_LEN,"\x0E\x00\x00\x0F\x00\x00\x0A\x9D\xED\xA2\x90\x04", 0x0C);
	    NEWBLK_LEN=NEWBLK_LEN+0x0C;
		*/

		buf=malloc(0x1000);
		outbuf=malloc(0x1000);

		memset(buf,0,0x1000);
		memset(outbuf,0,0x1000);

		// first char not count 
		// last 0x14 + BC is sha1 hash
		tlen=0x80-0x14-1-1;
		memcpy(buf,NEWBLK+1,tlen);
		memcpy(buf+tlen,NEWBLK+0x80,NEWBLK_LEN-0x80);
		tlen=tlen+NEWBLK_LEN-0x80;

		// show data for hashing
		show_memory(buf, tlen, "NEWBLK 2 input");

		// making sha1 hash
		_get_sha1_data(buf,tlen,outbuf,1);


		// show 
		show_memory(outbuf, 0x14, "NEWBLK(hash) 2 OUTPUT");

		// copy sha1 to new blk, at end, before BC
		memcpy(NEWBLK+0x80-0x14-1,outbuf,0x14);

	};


	show_memory(NEWBLK, NEWBLK_LEN, "NEWBLK2 new OUTPUT");


	///////////////////////
	//RSA sign
	///////////////////////
	//for sign newblk with our(xoteg) private key
	if (1) {
		char *buf;
		char *outbuf;


		buf=malloc(0x1000);
		outbuf=malloc(0x1000);

		memset(buf,0,0x1000);
		memset(outbuf,0,0x1000);


		//copy challenge template
		memcpy(buf,NEWBLK,0x80);
		
		//print newblk data
		//before RSA sign-ing
		show_memory(buf, 0x80, "newblk 2 RSA SIGN input");

		//make rsa sign
		_get_sign_data(buf, 0x80, outbuf);

		////copy rsa sign to challenge_response buffer
		////for send this response in next pkt
		memcpy(NEWBLK,outbuf,0x80);

		//print rsa signed newblk data
		show_memory(outbuf, 0x80, "newblk 2 RSA SIGN output");

	};
	


	//////////////////////////////////////////////////
	// modify sign new block with hash on cred+chatid , in aes data
	//////////////////////////////////////////////////
	//memcpy(aes_41data4+0x31,aes_41data4_newblk,0x80);



	
	//memset(buf4,0,sizeof(buf4));
  	//buf4_len=encode41_sess3pkt4(buf4, sizeof(buf4));
	//show_memory(buf4, buf4_len, "sess3pkt4");


    return 0;
};


//
// newblk with msg prepare
//
unsigned int make_tcp_client_prepare_newblk_msg() {
	char result[0x1000];
	u8 recvbuf[0x1000];
	char header41[0x100];
	int i;
	int j;
	int len;
	int tmplen;
	int recvlen;
	int blkseq;
	int remote_blkseq;
	char *pkt;


	u8 buf1[0x1000];
	int buf1_len;
	u8 buf1header[0x10];
	int buf1header_len;

	u8 buf2[0x1000];
	int buf2_len;
	u8 buf2header[0x10];
	int buf2header_len;

	u8 buf3[0x1000];
	int buf3_len;
	u8 buf3header[0x10];
	int buf3header_len;

	u8 buf4[0x1000];
	int buf4_len;
	u8 buf4header[0x10];
	int buf4header_len;

	u8 buf5[0x1000];
	int buf5_len;
	u8 buf5header[0x10];
	int buf5header_len;


	u8 buf_newblk3[0x1000];
	int buf_newblk3_len;



	///////////////////////////////
	// thirth block3 41
	///////////////////////////////

	// uic crc

	memset(NEWBLK,0,sizeof(NEWBLK));
	NEWBLK_LEN=0;

	NEWBLK[0]=0x6A;
    NEWBLK_LEN++;


	/////////////////////////////
	// SHA1 digest 0
	/////////////////////////////
	// for make digest at the _start_ of newbkl
	// crypted credentials(0x100) + chatid(0x24)
	if (1) {
		char *buf;
		char *outbuf;
		uint tlen;

		buf=malloc(0x1000);
		outbuf=malloc(0x1000);

		memset(buf,0,0x1000);
		memset(outbuf,0,0x1000);

		// credentials
		memcpy(buf, CREDENTIALS, CREDENTIALS_LEN);

		// + chatid 
		//memcpy(buf+4+0x100,"#xoteg_iam/$xot_iam;4fef7b015cb20ad0",0x24);
		memcpy(buf+CREDENTIALS_LEN,CHAT_STRING,strlen(CHAT_STRING));
		tlen=CREDENTIALS_LEN+strlen(CHAT_STRING);

		// show data for hashing
		show_memory(buf, tlen, "CHATID 3 input");

		// making sha1 hash
		_get_sha1_data(buf,tlen,outbuf,1);

		// show 
		show_memory(outbuf, 0x14, "CHATID(hash) 3 OUTPUT");

		// copy sha1 to new blk, at start+1
		memcpy(NEWBLK+1,outbuf,0x14);
		NEWBLK_LEN+=0x14;

	};


	
	//////////////////////////////////////////////////
	// modify chatid in newblk , in aes data
	//////////////////////////////////////////////////
	//memcpy(aes_41data3_newblk+0x15,"#xoteg_iam/$xot_iam;4fef7b015cb20ad0",0x24);
	//memcpy(aes_41data3_newblk+0x15,CHAT_STRING,0x24);

	memcpy(NEWBLK+NEWBLK_LEN,CHAT_STRING,strlen(CHAT_STRING));
	NEWBLK_LEN+=strlen(CHAT_STRING);

	
	memset(buf_newblk3,0,sizeof(buf_newblk3));
  	buf_newblk3_len=encode41_newblk3(buf_newblk3, sizeof(buf_newblk3));
	show_memory(buf_newblk3, buf_newblk3_len, "buf_newblk3");


	debuglog("Check newblk3 41 packing:\n");
	main_unpack(buf_newblk3, buf_newblk3_len);
	do_proto_log(buf_newblk3, buf_newblk3_len, "newblk3_decode");


	tmplen=buf_newblk3_len;
	if(1){
		int tlen_ost;
		int tlen_need;
		int tlen_first;
		int tlen_second;

		tlen_ost=0x80-NEWBLK_LEN-0x15;
		tlen_need=buf_newblk3_len;

		if (tlen_ost < tlen_need){
			tlen_first=tlen_ost;
			tlen_second=tlen_need-tlen_first;
			tmplen=tlen_first;
		};
	
	};


	// middle of newblk .. some 41 data..
    memcpy(NEWBLK+NEWBLK_LEN,buf_newblk3,tmplen);
	NEWBLK_LEN+=tmplen;

	if (NEWBLK_LEN+0x15 != 0x80) {
			show_memory(NEWBLK,0x80,"newblk:");
			debuglog("NEWBLK2 LEN encode error, LEN=0x%08X\n",NEWBLK_LEN+0x15);
			return -1;
	};

	NEWBLK[0x7f]=0xBC;

	
	/////////////////////////////
	// SHA1 digest 1
	/////////////////////////////
	// for make digest at the end of newblk
	// data under crypto(0x80) + cleartext data after(0x0a)
	if (1) {
		char *buf;
		char *outbuf;
		u32 tlen;


		NEWBLK_LEN=0x80;

		if ( tmplen!= buf_newblk3_len ){
			// aes41
			tlen=buf_newblk3_len-tmplen;
			memcpy(NEWBLK+NEWBLK_LEN,buf_newblk3+tmplen,tlen);
			NEWBLK_LEN+=tlen;
		};



		/*
		// message right after newblk
		memcpy(NEWBLK+NEWBLK_LEN,"\x02",1);
		NEWBLK_LEN++;

		memcpy(NEWBLK+NEWBLK_LEN,MSG_TEXT,strlen(MSG_TEXT));
		NEWBLK_LEN+=strlen(MSG_TEXT);

		memcpy(NEWBLK+NEWBLK_LEN,"\x00",1);
		NEWBLK_LEN++;
		*/


		buf=malloc(0x1000);
		outbuf=malloc(0x1000);

		memset(buf,0,0x1000);
		memset(outbuf,0,0x1000);


		// first char not count 
		// last 0x14 + BC is sha1 hash
		tlen=0x80-0x14-1-1;
		memcpy(buf,NEWBLK+1,tlen);		
		memcpy(buf+tlen,NEWBLK+0x80,NEWBLK_LEN-0x80);
		tlen=tlen+NEWBLK_LEN-0x80;

		// show data for hashing
		show_memory(buf, tlen, "NEWBLK 3 input");

		// making sha1 hash
		_get_sha1_data(buf,tlen,outbuf,1);


		// show 
		show_memory(outbuf, 0x14, "NEWBLK(hash) 3 OUTPUT");

		// copy sha1 to new blk, at end, before BC
		memcpy(NEWBLK+0x80-0x14-1,outbuf,0x14);

	};

	show_memory(NEWBLK, NEWBLK_LEN, "NEWBLK3 new OUTPUT");


	///////////////////////
	//RSA sign
	///////////////////////
	//for sign newblk with our(xoteg) private key
	if (1) {
		char *buf;
		char *outbuf;


		buf=malloc(0x1000);
		outbuf=malloc(0x1000);

		memset(buf,0,0x1000);
		memset(outbuf,0,0x1000);


		//copy challenge template
		memcpy(buf,NEWBLK,0x80);
		
		//print newblk data
		//before RSA sign-ing
		show_memory(buf, 0x80, "newblk 3 RSA SIGN input");

		//make rsa sign
		_get_sign_data(buf, 0x80, outbuf);

		////copy rsa sign to challenge_response buffer
		////for send this response in next pkt
		memcpy(NEWBLK,outbuf,0x80);

		//print rsa signed newblk data
		show_memory(outbuf, 0x80, "newblk 3 RSA SIGN output");

	};
	


	//////////////////////////////////////////////////
	// modify sign new block with hash on cred+chatid , in aes data
	//////////////////////////////////////////////////
	//memcpy(aes_41data3+0x35,aes_41data3_newblk,0x80);

	
	//memset(buf3,0,sizeof(buf3));
  	//buf3_len=encode41_sess4pkt3(buf3, sizeof(buf3));
	//show_memory(buf3, buf3_len, "sess4pkt3");


};

