// relayrecv2.c: Defines the entry point for the console application.
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

int main_skypeclient_tcpconnect_sess1();

extern int parse_input_line(char *line, u32 *secret_p, u32 *secret_q, char *str_skypename, char *user_cred);
extern int parse_input_line2(char *line, char *str_remote_skype, char *destip, char *destport);
extern int restore_user_keypair(u32 *secret_p, u32 *secret_q, u8 *public_key, u8 *secret_key);
extern int show_memory(char *mem, int len, char *text);

extern char REMOTE_MSG[0x1000];

extern u8 CREDENTIALS[0x105];
extern char xoteg_sec[0x81];
extern char xoteg_pub[0x81];

extern u8 CHAT_STRING[0x100];
extern u8 REMOTE_NAME[0x100];
extern u8 LOCAL_NAME[0x100];
extern u8 MSG_TEXT[0x1000];

extern u8 CHAT_PEERS[0x100];
extern u8 CHAR_RND_ID[0x100];

extern u8 CHAT_PEERS_REVERSED[0x100];

extern char global_destip[0x1000];
extern unsigned short global_destport;

extern int global_fail;

extern int relay_connect_mode;

extern miracl *mip;


int relay_parse_cmd_lines_lib(char *argv1_cred) {
	int ret;
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


	if ((argv1_cred!=NULL) && (strlen(argv1_cred)>0)){
		parse_input_line(argv1_cred, secret_p, secret_q, (char*)&str_skypename, (char*)&user_cred);
	}else{
		debuglog("please specify inputs parameters\n");
		return -1;
	};
	debuglog("skypename=%s\n",str_skypename);
	show_memory(user_cred,0x100,"cred:");

	memcpy(CREDENTIALS, "\x00\x00\x00\x01", 4);
	memcpy(CREDENTIALS+4,user_cred,0x100);


	restore_user_keypair(secret_p, secret_q, public_key, secret_key);


	memcpy(xoteg_pub,public_key,0x80);
	memcpy(xoteg_sec,secret_key,0x80);

	show_memory(xoteg_pub,0x80,"xoteg_pubkey:");
	show_memory(xoteg_sec,0x80,"xoteg_seckey:");

	show_memory(CREDENTIALS,0x104,"CREDENTIALS:");

    ret = decode_profile_for_time_check(CREDENTIALS, 0x104);
    if (ret<0) { return -101; };

	strcpy(LOCAL_NAME,str_skypename);
	
	// hmmm? some changes in new proto?
	strcat(CHAT_STRING,"#");
	strcat(CHAT_STRING,str_skypename);
	strcat(CHAT_STRING,"/$");
	strcat(CHAT_STRING,REMOTE_NAME);
	strcat(CHAT_STRING,";");
	strcat(CHAT_STRING,CHAR_RND_ID);


    memset(CHAT_PEERS, 0, sizeof(CHAT_PEERS));

	strcat(CHAT_PEERS, str_skypename);
	strcat(CHAT_PEERS, " ");
	strcat(CHAT_PEERS, REMOTE_NAME);


    memset(CHAT_PEERS_REVERSED, 0, sizeof(CHAT_PEERS_REVERSED));

	strcat(CHAT_PEERS_REVERSED, REMOTE_NAME);
	strcat(CHAT_PEERS_REVERSED, " ");
	strcat(CHAT_PEERS_REVERSED, str_skypename);

	debuglog("CHAT_STRING: %s\n",CHAT_STRING);
    debuglog("LOCAL_NAME: %s\n",LOCAL_NAME);
    debuglog("REMOTE_NAME: %s\n",REMOTE_NAME);
    debuglog("CHAT_PEERS: %s\n",CHAT_PEERS);

 	debuglog("\nMSG_TEXT: %s\n",MSG_TEXT);

	return 0;
}


//
// main function suitable to call from library
//
int relayrecv_main(char* static_myip, char* static_username, char* static_uservcard, char* msg){
	int ret;
	char *argv1_cred;
	char *argv2_uservcard;
	char cred[0x1000];
	char uservcard[0x10000];
    char MY_ADDR[100];
	char vcard_tok[0x1000];
    char* split_vcard;
	FILE *fp;
    char *vcards[10];
    int vcards_cnt;
    int i;


    mip = mirsys(100, 0);

    tcp_talk_init();

    do_init_logfiles();

    make_setup_global_init();

    relay_connect_mode = 1;

	argv1_cred = read_cred_from_file(cred, sizeof(cred));
	argv2_uservcard = strcpy(uservcard, static_uservcard);

	//strcpy(MSG_TEXT, static_msg);
    /*
	strcpy(uservcard, static_uservcard);
	strcpy(REMOTE_NAME, static_username);
    strncpy(MY_ADDR, static_myip, 100);
    */

    // converting to utf8 and ascii with copy
    UnicodeToAscii(uservcard, static_uservcard);
    UnicodeToAscii(REMOTE_NAME, static_username );
    UnicodeToAscii(MY_ADDR, static_myip);

	ret = relay_parse_cmd_lines_lib(argv1_cred);

	if (ret == -1){
		debuglog("Input data parsing failed.\n");
		return -1;
	}

	fp=fopen("_relay.txt","w");
    fclose(fp);

    vcards_cnt = 0;
    i = 0;
    split_vcard = strtok(uservcard,"\r\n");
    while(split_vcard != NULL) {
        vcards[i] = strdup(split_vcard);
        i++;
        //next string
        split_vcard = strtok(NULL,"\r\n");
    };
    vcards_cnt = i;

    debuglog("vcards_cnt = %d\n", vcards_cnt);

    for (i=0; i<vcards_cnt; i++) {
            strcpy(vcard_tok, vcards[i]);
            debuglog("Vcard_newline: %s\n",vcard_tok);
			if (1) {
				fp=fopen("_relay.txt","a");
				if (fp==NULL){
					debuglog("logfile creation error\n");
					return -1;
				};
                fprintf(fp,"Vcard_newline: %s\n",vcard_tok);
				fclose(fp);
			};

            ret = skyrelay2_main(MY_ADDR, REMOTE_NAME, vcard_tok);
            debuglog("skyrelay2_main ret %d\n", ret);
            if (ret == -1) {
                tcp_talk_deinit();
                tcp_talk_init();
            };
            if (ret == 1) {
                ret = on_relay_success();
                if (ret==1) {
                    strcpy(msg, REMOTE_MSG);
                };
                tcp_talk_deinit();
            	return ret;
            };
            if (ret == 0) {
                // TODO
                ;
            };

        debuglog("vcards_loop = %d\n", vcards_cnt);
    }

    debuglog("vcards finish = %d\n", vcards_cnt);

    tcp_talk_deinit();

    // relay fail
    ret = -10;

	return ret;
};


int on_relay_success() {
    int ret;

    ret = relayrecv_skypeclient_tcpconnect_sess1();

	// ret = 1 -- succeed
	// ret = 0 -- some error occurred
	// ret = -1 -- some error occurred
    
    return ret;
};


int relayrecv_skypeclient_tcpconnect_sess1() {
    char *ip;
    unsigned short port;
    unsigned short seqnum;
    unsigned int rnd;
    int ret;

    srand( time(NULL) );
    
    ip=global_destip;
    port=global_destport;
    
    // do not need due to relay connect
    //ret = make_tcp_client_sess1_pkt0_handshake1(ip, port);

    init_headers();

    make_setup_prepare();

    // do not need due to relay connect
    //make_tcp_client_sess1_pkt1(ip, port);

    global_fail = 0;

    ret = make_tcp_client_sess1_pkt2(ip, port);
    debuglog("pkt2 ret: %d\n", ret);
    if (ret <= 0) {
        return -1;
    };
    if (global_fail == 1) {
        return -1;
    };
    debuglog("pkt2 OK\n");

    ret = make_tcp_client_sess1_pkt4();
    if (ret < 0) {
        remove_messages_from_db();
    };

    //debuglog("pkt4 OK\n");
    //Sleep(3000);

    clear_headers();

    return ret;
};


