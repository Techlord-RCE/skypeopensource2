// skypush3.c : Defines the entry point for the console application.
//

#include <stdio.h>
#include <stdlib.h>

#include <string.h>  
#include <winsock.h>
#include <windows.h>  
#include <sys/types.h>  
#include <time.h>
#include <errno.h>  

#include "short_types.h"

extern int main_unpack(u8 *indata, u32 inlen);
extern int main_unpack_get (u8 *indata, u32 inlen, u8 *ipinfo, u32 *ipinfo_len);
extern int slot_find(u8 *str);

extern int make_udp_push_pkt1(char *ourip,char *destip, u16 seqnum, u32 rnd, char *pkt, int *pkt_len);
extern int process_udp_push_pkt1(char *pkt,int pkt_len,char *ourip,char *destip);

extern int udp_talk(char *remoteip, u16 remoteport, char *buf, int len, char *result, int result_maxlen, int *retsock);
extern int udp_recv(char *remoteip, unsigned short remoteport, char *result, int result_maxlen, int *retsock);

extern int show_memory(char *mem, int len, char *text);


//int DEBUG = 1;

unsigned int global_connid;
char *global_connectip;
unsigned short global_connectport;

// 
// status of udp remote node
//
int status_udp_print(int retcode, char *our_public_ip){
    
    switch (retcode) {
        case 1:
            printf("this is supernode! our public ip: %s\n",our_public_ip);
            break;
        case -1:
            printf("socket comm error\n");
            break;
        case -2:
            printf("timeout\n");
            break;
        case -3:
            printf("not skype\n");
            break;
        case -4:
            printf("skype client\n");
            break;
        default:
            printf("unknown case, %d\n",retcode);
    };

    return 0;
};


int snode_udp_push1(char *destip, u16 destport, char *our_public_ip) {
    u16 seqnum;
    u32 rnd;
    char resp[0x1000];
    int resp_len;
    char pkt[0x1000];
    int pkt_len;
    int retcode;
    int retsock;

    seqnum=rand() % 0x10000;

    //seqnum = 0xBAB4;

    rnd=rand() % 0x10000;
    rnd+=(rand() % 0x10000)*0x10000;

    //rnd = 0xFD0D42D7;

    // pkt1
    retcode=make_udprelay_pkt1(our_public_ip, destip,seqnum,rnd,(char *)pkt,&pkt_len);
    if (retcode==-1) {
        //printf("prepare error\n");
        return -1;
    };
    resp_len=udp_talk(destip,destport,pkt,pkt_len,resp,sizeof(resp), &retsock);
    if (resp_len<0) {
        printf("socket comm error\n");
        return -1;
    };
    if (resp_len==0) {
        printf("timeout\n");
        return -2;
    };
    
    //if (DEBUG) printf("part len:0x%08X\n",resp_len);
    printf("part len:0x%08X\n", resp_len);

    retcode=process_udprelay_pkt1(resp,resp_len,our_public_ip,destip);
    if (retcode==-1) {
        //printf("not skype\n");
        return -3;
    };
    

    //printf("our public ip: %s\n",our_public_ip);
    //printf("this is supernode\n");

    return 1;
};


//
// Supernode udp user request
//
int snode_udp_push3(char *our_public_ip, char *destip, u16 destport, char *remote_name, char *remote_vcard) {
    u16 seqnum;
    u32 rnd;
    char resp[0x1000];
    int resp_len;
    char pkt[0x1000];
    int pkt_len;
    int retcode;
    int retsock;


    seqnum=rand() % 0x10000;

    //seqnum = 0xBAB4;

    rnd=rand() % 0x10000;
    rnd+=(rand() % 0x10000)*0x10000;

    //rnd = 0xFD0D42D7;

    // pkt3
    retcode=make_udprelay_pkt3(our_public_ip, destip, seqnum, rnd, remote_name, remote_vcard, (char *)pkt, &pkt_len);
    if (retcode==-1) {
        //printf("prepare error\n");
        return -1;
    };
    resp_len=udp_talk(destip,destport,pkt,pkt_len,resp,sizeof(resp), &retsock);
    if (resp_len<0) {
        printf("socket comm error\n");
        return -1;
    };
    if (resp_len==0) {
        printf("timeout\n");
        return -2;
    };
    
    //if (DEBUG) printf("part len:0x%08X\n",resp_len);
    printf("part len:0x%08X\n",resp_len);

    retcode=process_udprelay_pkt3(resp,resp_len,our_public_ip,destip);
    if (retcode==-1) {
        //printf("not skype\n");
        return -3;
    };

    //printf("our public ip: %s\n",our_public_ip);
    //printf("this is supernode\n");

    return 1;
};


//
// Get Relays from users supernode
//
int main_skypush_getrelays(char* myip, char *destip, unsigned short destport){
    char our_public_ip[128];
    int ret;
    char *MY_ADDR;

    MY_ADDR=strdup(myip);
    strcpy(our_public_ip, MY_ADDR);

    printf("Push request to target node ip: %s\n", destip);
    printf("Our IP: %s\n", our_public_ip);

    ret=snode_udp_push1(destip, destport, our_public_ip);

    return ret;
};



//
// Send udp push packet
//
int main_skypush_connect(char* myip, char *destip, unsigned short destport, char *relayip, unsigned short relayport, int conn_id, char *remote_name, char *remote_vcard) {
    char our_public_ip[128];
    int ret;
    char *MY_ADDR;

    MY_ADDR=strdup(myip);
    strcpy(our_public_ip, MY_ADDR);

    global_connid = conn_id;
    global_connectip = relayip;
    global_connectport = relayport;

    printf("Push request to target node ip: %s\n", destip);
    printf("Our IP: %s\n", our_public_ip);
    printf("Got conn_id: 0x%08X\n", global_connid);

    ret=snode_udp_push3(our_public_ip, destip, destport, remote_name, remote_vcard);

    return ret;
};
