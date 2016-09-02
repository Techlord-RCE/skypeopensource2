//
// goodrecvrelay3.c : Defines the entry point for the console application.
//

#include <stdio.h>
#include <stdlib.h>

#include <string.h>  
#include <time.h>

#include <fcntl.h>
#include <io.h>

#include "miracl_lib/miracl.h"
#include "short_types.h"

#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")


extern unsigned int make_tcp_client_sess1_pkt1(char *ip, unsigned short port);
extern unsigned int make_tcp_client_sess1_pkt2(char *ip, unsigned short port);
extern unsigned int make_tcp_client_sess1_pkt3();
extern unsigned int make_tcp_client_sess1_pkt4();

extern int decode_profile(char *credentials, int credentials_len);

int make_dh384_handshake(char *ip, unsigned short port);

extern int parse_input_line(char *line, u32 *secret_p, u32 *secret_q, char *str_skypename, char *user_cred);
extern int parse_input_line2(char *line, char *str_remote_skype, char *destip, char *destport);
extern int restore_user_keypair(u32 *secret_p, u32 *secret_q, u8 *public_key, u8 *secret_key);
extern int show_memory(char *mem, int len, char *text);

extern u8 CREDENTIALS[0x105];
extern char xoteg_sec[0x81];
extern char xoteg_pub[0x81];

extern u8 CHAT_STRING[0x100];
extern u8 REMOTE_NAME[0x100];
extern u8 LOCAL_NAME[0x100];
extern u8 CHAT_PEERS[0x100];

extern u8 CHAR_RND_ID[0x100];
extern u8 MSG_TEXT[0x1000];

extern u8 CHAT_PEERS_REVERSED[0x100];

extern u32 LOCAL_SESSION_ID;

extern char global_destip[0x1000];
extern unsigned short global_destport;


miracl *mip;
	

int parse_cmd_lines_lib(char *argv1_cred, char *argv2_userip) {
	int len;
	u32 secret_p[17], secret_q[17];
	char public_key[0x81];
	char secret_key[0x81];

	char str_skypename[0x1000];
	char user_cred[0x101];

	char str_remote_skype[1024];
	char destip[1024];
	char destport[1024];

	int fd;

	memset(public_key,0,sizeof(public_key));
	memset(secret_key,0,sizeof(secret_key));

	mip=mirsys (100, 0);


	if ((argv1_cred!=NULL) && (strlen(argv1_cred)>0)){
		parse_input_line(argv1_cred, secret_p, secret_q, (char*)&str_skypename, (char*)&user_cred);
	}else{
		debuglog("please specify inputs parameters\n");
		return -1;
	};
	debuglog("skypename=%s\n",str_skypename);
	show_memory(user_cred,0x100,"cred:");

	memcpy(CREDENTIALS+4,user_cred,0x100);



	if ((argv2_userip!=NULL) && (strlen(argv2_userip)>0)){
		parse_input_line2(argv2_userip, (char *)&str_remote_skype, (char *)&destip, (char *)&destport);
	}else{
		debuglog("please specify inputs parameters\n");
		return -1;
	};
	debuglog("remote_skypename=%s\n",str_remote_skype);
	debuglog("destip=%s\n",destip);
	debuglog("destport=%s\n",destport);

	strcpy(global_destip,destip);
	global_destport=atoi(destport);


	restore_user_keypair(secret_p, secret_q, public_key, secret_key);


	memcpy(xoteg_pub,public_key,0x80);
	memcpy(xoteg_sec,secret_key,0x80);

	show_memory(xoteg_pub,0x80,"xoteg_pubkey:");
	show_memory(xoteg_sec,0x80,"xoteg_seckey:");

	show_memory(CREDENTIALS,0x104,"CREDENTIALS:");


    decode_profile_for_time_check(CREDENTIALS, 0x104);

	
	strcpy(REMOTE_NAME,str_remote_skype);
	strcpy(LOCAL_NAME,str_skypename);

	// hmmm? some changes in new proto?
	strcat(CHAT_STRING,"#");
	strcat(CHAT_STRING,str_skypename);
	strcat(CHAT_STRING,"/$");
	strcat(CHAT_STRING,REMOTE_NAME);
	strcat(CHAT_STRING,";");
	strcat(CHAT_STRING,CHAR_RND_ID);

    /* 
    //hmmm, hz
	strcat(CHAT_STRING_REVERSED,"#");
	strcat(CHAT_STRING_REVERSED,REMOTE_NAME);
	strcat(CHAT_STRING_REVERSED,"/$");
	strcat(CHAT_STRING_REVERSED,str_skypename);
	strcat(CHAT_STRING_REVERSED,";");
	strcat(CHAT_STRING_REVERSED,CHAR_RND_ID);
    */


    memset(CHAT_PEERS, 0, sizeof(CHAT_PEERS));

	strcat(CHAT_PEERS, str_skypename);
	strcat(CHAT_PEERS, " ");
	strcat(CHAT_PEERS, REMOTE_NAME);


    memset(CHAT_PEERS_REVERSED, 0, sizeof(CHAT_PEERS_REVERSED));

	strcat(CHAT_PEERS_REVERSED, REMOTE_NAME);
	strcat(CHAT_PEERS_REVERSED, " ");
	strcat(CHAT_PEERS_REVERSED, str_skypename);

	//debuglog("Hello World!\n");

	debuglog("CHAT_STRING: %s\n",CHAT_STRING);
    debuglog("REMOTE_NAME: %s\n",REMOTE_NAME);
    debuglog("CHAT_PEERS: %s\n",CHAT_PEERS);

 	debuglog("\nMSG_TEXT: %s\n",MSG_TEXT);

	return 0;
}

char *read_cred_from_file(char *cred, int cred_max_len){
	int fd;
	int len;

	fd=open("a_cred.txt",O_RDONLY);
	if (fd<=0){
		debuglog("file open error, not exist \"a_cred.txt\" file\n");
		return 0;
	};

	len=read(fd, cred, cred_max_len);
	close(fd);
    
	if (len<=0){
		debuglog("file read error\n");
		return 0;
	};
	if (len>=cred_max_len){
		debuglog("file too big\n");
		return 0;
	};

	cred[len]=0;

	return cred;
};


int skypechat_main(char* static_userip) {
	int ret;
	char *argv1_cred;
	char *argv1_userip;
	char cred[0x1000];
	char userip[0x1000];

    do_init_logfiles();

    make_setup_global_init();

	argv1_cred = read_cred_from_file(cred, sizeof(cred));
    if (argv1_cred == 0) { return -1; };
	argv1_userip = strcpy(userip, static_userip);
    if (argv1_userip == 0) { return -1; };

	ret = parse_cmd_lines_lib(argv1_cred, argv1_userip);

	if (ret == -1){
		debuglog("Input data parsing failed.\n");
		return -1;
	}

	// ret = 1 -- succeed
	// ret = 0 -- some error occurred
	ret = main_skypeclient_tcpconnect_sess1();

	return ret;
};


int main_skypeclient_tcpconnect_sess1(){
	char *ip;
	unsigned short port;
	unsigned int rnd;
	int ret;

	srand( time(NULL) );
		
	ip=global_destip;
	port=global_destport;

    tcp_talk_init();

    init_headers();

    make_setup_prepare();

	ret = make_dh384_handshake(ip, port);
    if (ret < 0) { 
        tcp_talk_deinit();
        return -1; 
    };

	ret = make_tcp_client_sess1_pkt1(ip, port);
    if (ret < 0) { 
        tcp_talk_deinit();
        return -1; 
    };

	ret = make_tcp_client_sess1_pkt2(ip, port);
    if (ret < 0) { 
        tcp_talk_deinit();
        return -1; 
    };

	ret = make_tcp_client_sess1_pkt4();
    if (ret < 0) {
        remove_messages_from_db();
    };

    clear_headers();

    tcp_talk_deinit();

	return ret;
};

