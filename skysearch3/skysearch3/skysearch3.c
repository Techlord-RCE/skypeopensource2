// skysearch3.c -- search given skype username on skype network
//


#include <stdio.h>
#include <stdlib.h>

#include <string.h>  

#include <time.h>
#include <errno.h>  

#pragma comment(lib, "ws2_32.lib")

#include "miracl_lib/miracl.h"

#include "short_types.h"

#include "slots_util.h"


miracl *mip;

extern int get_profiles(u8 *buf, u32 len);

extern int main_unpack(u8 *indata, u32 inlen);
extern int main_unpack_get (u8 *indata, u32 inlen, u8 *ipinfo, u32 *ipinfo_len);

int slot_find(u8 *str);

extern int make_udp_reqsearch_pkt1(char *destip, u16 seqnum, u32 rnd, char *skypeuser, char *pkt, int *pkt_len);
extern int process_udp_reqsearch_pkt1(char *pkt, int pkt_len, char *destip);

extern int udp_talk(char *remoteip, u16 remoteport, char *buf, int len, char *result);
extern int udp_recv(char *remoteip, unsigned short remoteport, char *result);

extern int show_memory(char *mem, int len, char *text);

extern int decode_profile(u8 *remote_profile, u8 *pubkey, u8 *data, u8 *skypename);


// dont change !!!
// or change also in comm_sock.c
#define BUF_SIZE 0x20000


char MY_ADDR[0x100];


u8 bigbuf[0x100000];
u32 bigbuf_count=0;


struct _slots slots[2048];



//
// Supernode udp user request
//
int snode_udp_reqsearch(char *destip, u16 destport, char *skypeuser) {
    u16 seqnum;
    u32 rnd;

    char resp[BUF_SIZE];
    int resp_len;

    char pkt[BUF_SIZE];
    int pkt_len;

    int retcode;

    seqnum=rand() % 0x10000;
    //seqnum = 0x30D3;

    rnd=rand() % 0x10000;
    rnd+=(rand() % 0x10000)*0x10000;
    
    bigbuf_count=0;

    printf("---\n");
    printf("Our public ip: %s\n", MY_ADDR);
    printf("---\n");


    // pkt1
    make_udp_reqsearch_pkt1(destip,seqnum,rnd,skypeuser,(char *)pkt,&pkt_len);
    resp_len=udp_talk(destip,destport,pkt,pkt_len,resp);
    if (resp_len<0) {
        printf("socket comm error\n");
        return -1;
    };
    if (resp_len==0) {
        printf("timeout\n");
        return -2;
    };


    retcode=process_udp_reqsearch_pkt1(resp, resp_len, destip);
    if (retcode==-1) {
        printf("not skype\n");
        return -3;
    };
    
    do {

        resp_len=udp_recv(destip,destport,resp);
        if (resp_len<0) {
            printf("socket comm error\n");
            //return -1;
            break;
        };
        if (resp_len==0) {
            printf("timeout\n");
            //return -2;
            if (bigbuf_count<0x188){
                //return -2;
            };
            break;
        };
        retcode=process_udp_reqsearch_pkt1(resp, resp_len, destip);
        if (retcode==-1) {
            printf("not skype\n");
            //return -3;
            break;
        };

    } while(resp_len>0);

    if (bigbuf_count == 0) {
        printf("Error2. Some empty strange pkt received.\n");
        printf("Possible our_public_ip address error.\n");

        return 0;
    };

    // need check for 00-01: 01 return
    if (bigbuf_count < 0x188) {
        int code;

        printf("Recv data too small for 0x188 block\n");
        printf("Checking for error...\n");
        get_00_01_blob(bigbuf, bigbuf_count, &code);
        printf("Returned code: %d\n", code);
        if (code == 1) {
            printf("Supernode returned 00-01: 01 code\n");
            printf("Trying next node...\n");

            return 100;
        };
    };


    // yet in process_udp_reqsearch_pkt1
    //main_unpack (bigbuf, bigbuf_count);

    // version 1, not unsed 41 unpack
    //get_profiles(bigbuf, bigbuf_count);

    // version 2, with 41 unpack for get exact size of buffer
    get_profiles2(bigbuf, bigbuf_count);

    //printf("our public ip: %s\n",our_public_ip);
    printf("this is supernode\n\n");

    return 1;   
};



int do_request_user_vcard(char *skypeuser) {
    u32 userslot;
    int ret;
    char *destip;
    u16 destport;
    int i;

    userslot=slot_find(skypeuser);
    printf("slot: #%d (0x%08X)\n",userslot,userslot);
    printf("nodes in slot: %d\n",slots[userslot].snodes_len);

    for (i=0;i<slots[userslot].snodes_len;i++){

        destip = slots[userslot].snodes[i].ip;
        destport = atoi(slots[userslot].snodes[i].port);

        printf("sending search request\n");
        printf("target node ip: %s\n",destip);

        ret=snode_udp_reqsearch(destip, destport, skypeuser);
        if (ret == 100){
            // ask next node 
        } else {
            //return -1;

            // comment this break for do ask all nodes
            //break;
        };

    };

    return 0;
};


//
// Function main_skysearch_one (for call from lib)
//
int main_skysearch_one(char *username, char *vcard_buf, int maxlen) {
    int ret;

    sockets_init();

    init_vcard_array();

	load_slots_file();
    ret = do_request_user_vcard(username);

    save_vcards_tomem(vcard_buf, maxlen);

    sockets_destroy();

    return ret;
};


//
// Function main_skysearch_many (for call from lib)
//
int main_skysearch_many(int argc, char* argv[], char *vcard_buf, int maxlen) {
    int ret;
	int i;
	char *user;

    sockets_init();

    init_vcard_array();

	load_slots_file();
    for(i=1; i<argc; i++) {
        user = argv[i];
        printf("Searching user: %s\n", user);
        ret = do_request_user_vcard(user);
    };

    save_vcards_tomem(vcard_buf, maxlen);

    sockets_destroy();

    return ret;
};


//
// Function main_skysearch_getslots (for call from lib)
// my_addr - output parameter
//
int main_skysearch_getslots(int argc, char* argv[], char *myip) {
	char *destip;
	u16 destport;
	char *user;
	char *skypeuser;
	char our_public_ip[128];
	u32 userslot;
	int ret;
	u32 i;
    int n_argc;
    int n_argv[0x1000];

	srand( time(NULL) );

	mip=mirsys (100, 0);

    memset(MY_ADDR, 0x00, sizeof(MY_ADDR));

    sockets_init();

    n_argc = 0;
    for(i=0; i<argc; i++) {
        user = argv[i];
    	userslot=slot_find(user);
        printf("%s slot: #%d (0x%08X)\n", user, userslot, userslot);
        n_argv[n_argc] = userslot;
        n_argc++;

        if (n_argc==10) {
            // get and fill slots
        	ret = main_get_slotinfo(n_argc, n_argv);
            n_argc = 0;
        };
    };
    // last, not full 10, part
    if (n_argc>0){
        // get and fill slots
      	ret = main_get_slotinfo(n_argc, n_argv);
    };
    printf("\n");

    sockets_destroy();

    if (strlen(MY_ADDR) <= 0) {
        return -1;
    };

    strncpy(myip, MY_ADDR, 100);

	return ret;	
};


int main_get_slotinfo(int n_argc, int n_argv[]) {
    char *ip;
    unsigned short port;
    unsigned short seqnum;
    unsigned int rndseq;
    int ret;

    srand(time(NULL));

    mip = mirsys(100, 0);
    
    // main
    ip=strdup("157.55.235.147");
    port=40030;

    // good one
    //ip=strdup("65.55.223.14");
    //port=40016;

    rndseq=rand() % 0x10000;

    if (n_argc > 10) {
        printf("[ERROR] List for username checking too big.\n");
        return -1;
    };

    seqnum = make_tcp_client_sess1_pkt0_handshake1(ip, port);
    make_tcp_client_sess1_pkt1(ip, port);
    ret = make_tcp_client_sess1_pkt3(ip, port, rndseq, n_argc, n_argv);

    printf("All done!\n");

    return ret;
}
