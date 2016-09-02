// skyrel3.c -- Skype connect to supernode and waiting incoming connection
//                                              
//


#include "relays_util.h"

#include "short_types.h"

extern struct _relays relays;


#define BUF_SIZE 8192



char *gnu_basename(char *path) {
    char *base = strrchr(path, '\\');
    return base ? base+1 : path;
};



// 
// status of tcp remote node
//
int status_tcp_print(int retcode){
    
    switch (retcode) {
        case 1:
            debuglog("this is supernode!\n");
            break;
        case -1:
            debuglog("socket comm error\n");
            break;
        case -2:
            debuglog("connection failed\n");
            break;
        case -3:
            debuglog("timeout\n");
            break;
        case -4:
            debuglog("not skype\n");
            break;
        case -5:
            debuglog("old skype client\n");
            break;
        case -6:
            debuglog("skype client, clients node dumped\n");
            break;
        default:
            debuglog("unknown case, %d\n",retcode);
    };

    return 0;
};


//
// Supernode tcp test
//
int snode_tcp_test(char *destip, u16 destport, int *conn_id) {
    u16 seqnum;
    u32 rnd;
    u32 remote_tcp_rnd;
    int last_recv_pkt_num;
    char resp[BUF_SIZE];
    int resp_len;
    char pkt[BUF_SIZE];
    int pkt_len;
    int retcode;
    int maxlen;

    
    maxlen=sizeof(resp)-1;

    last_recv_pkt_num=0;

    seqnum=rand() % 0x10000;

    rnd=rand() % 0x10000;
    rnd+=(rand() % 0x10000)*0x10000;


    tcp_talk_init();
    
    // pkt1
    //retcode=make_tcp_pkt1(rnd,  &remote_tcp_rnd, (char *)pkt, &pkt_len);
    retcode = make_dh384_handshake(destip, destport);
    if (retcode==-1) {
        //debuglog("build pkt fail\n");
        return -1;
    };

    /*
    resp_len=tcp_talk(destip,destport,pkt,pkt_len,resp,0);
    if (resp_len==-1) {
        //debuglog("socket comm error\n");
        tcp_talk_deinit();
        return -1;
    };
    if (resp_len==0) {
        //debuglog("connection failed\n");
        tcp_talk_deinit();
        return -2;
    };
    if (resp_len==-2) {
        //debuglog("timeout\n");
        tcp_talk_deinit();
        return -3;
    };
    */


    // pkt2
    retcode=make_tcp_pkt2(seqnum, rnd, (char *)pkt, &pkt_len);
    if (retcode==-1) {
        //debuglog("build pkt fail\n");
        return -1;
    };
    resp_len=tcp_talk(destip,destport,pkt,pkt_len,resp,0);
    if (resp_len==-1) {
        //debuglog("socket comm error\n");
        tcp_talk_deinit();
        return -1;
    };
    if (resp_len==0) {
        //debuglog("connection failed\n");
        tcp_talk_deinit();
        return -2;
    };
    if (resp_len==-2) {
        //debuglog("timeout\n");
        tcp_talk_deinit();
        return -3;
    };
    retcode=process_tcp_pkt2(resp, resp_len, conn_id);
    if (retcode==-1) {
        debuglog("parse pkt2 error\n");
        tcp_talk_deinit();
        return -1;
    };
    if (*conn_id == 0) {
        debuglog("conn_id not found\n");
        tcp_talk_deinit();
        return -1;
    };

    debuglog("waiting for connection\n");

    // recv additional data

    /*
    do{

        resp_len=tcp_talk_recv(destip,destport,resp,0);
        if (resp_len<0) {
            debuglog("pkt3, socket error\n");
            break;
        };

        if (resp_len>0){
            retcode=process_tcp_pkt3(resp,resp_len, &last_recv_pkt_num);
            if (retcode==-1) {
                debuglog("pkt3, parse error\n");
                break;
            };
        };

        debuglog("resp_len: %d\n",resp_len);
        Sleep(1000);

    } while(1);
    */

    //debuglog("this is supernode\n");

    return 1;
};


int main_skyrel(int *conn_id) {
    char ip[0x100];
    u32 ip_int;
    unsigned short port;
    int i;
    int ret;

    // supernode connection
    //ip=strdup("157.55.235.147");
    //port=40030;

    if (relays.relays_len <= 0) {
        debuglog("Relays array not found\n");
        debuglog("Did you do udp relays request first?\n");
        return -1;
    };

    // trying to do relay connect
    for (i = 0; i < relays.relays_len; i++) {
        ip_int = relays.relay[i].ip;
        sprintf(ip, "%u.%u.%u.%u", ip_int>>24, (ip_int>>16)&0xFF, (ip_int>>8)&0xFF, ip_int&0xFF);
        port = relays.relay[i].port;

        if (0) {
            strcpy(ip, "192.168.1.135");
            port = 14410;
            i = 100;
        };

        debuglog("Connecting to %s:%d...\n", ip, port);

        *conn_id = 0;
        ret=snode_tcp_test(ip, port, conn_id);
        status_tcp_print(ret);
        if ((ret) && (*conn_id > 0)) {
            // all ok, we are connected
            debuglog("Relay connecting done!\n");
            return i;
        };
    };

    debuglog("All relays checked. Relay connecting fail.\n");

    return 0;
};


//
// Supernode tcp relay answer
//
int snode_tcp_answer(int *retsock) {
    int last_recv_num;
    char resp[0x2005];
    int resp_len;
    int retcode;
    int resp_maxlen;
    u8 confirm[0x100];
    u32 confirm_len=0;

    int DEBUG_LEVEL = 100;

    resp_maxlen=sizeof(resp)-1;

    // pkt 3 recv
    resp_len=tcp_talk_recv2(resp);
    if (resp_len<0) {
        if (DEBUG_LEVEL>=100) debuglog("pkt3, socket error\n");
        tcp_talk_deinit();
        return -1;
    };
    if (resp_len==0){
        if (DEBUG_LEVEL>=100) debuglog("pkt3, connection closed unexpected\n");
        tcp_talk_deinit();
        return -1;
    };
    retcode=process_tcp_pkt3(resp, resp_len, &last_recv_num);
    if (retcode==-1) {
        if (DEBUG_LEVEL>=100) debuglog("pkt3, parse error\n");
        tcp_talk_deinit();
        return -1;
    };

    //global->last_recv_num=last_recv_num;


    retcode=make_tcp_pkt_confirm(last_recv_num, (char *)confirm, &confirm_len);
    if (retcode==-1) {
        if (DEBUG_LEVEL>=100) debuglog("build pkt fail confirm\n");
        return -1;
    };


    // pkt send confirm
    resp_len=tcp_talk_send(confirm, confirm_len);
    if (resp_len<0) {
        if (DEBUG_LEVEL>=100) debuglog("pkt3, socket error\n");
        tcp_talk_deinit();
        return -1;
    };


    debuglog("Confirm pkt send!\n");


    // pkt 3 recv
    resp_len=tcp_talk_recv2(resp);
    if (resp_len<0) {
        if (DEBUG_LEVEL>=100) debuglog("pkt3, socket error\n");
        tcp_talk_deinit();
        return -1;
    };
    if (resp_len==0){
        if (DEBUG_LEVEL>=100) debuglog("pkt3, connection closed unexpected\n");
        tcp_talk_deinit();
        return -1;
    };
    retcode=process_tcp_pkt_after_answer(resp, resp_len);
    if (retcode==-1) {
        if (DEBUG_LEVEL>=100) debuglog("pkt3, parse error\n");
        tcp_talk_deinit();
        return -1;
    };

    
    return 1;
};


//
// SkyRel answer check
//
unsigned int skyrel_answer() {
    int ret;
    int i=0;
    int retsock;

    ret=snode_tcp_answer(&retsock);
    if(ret!=1){
        return -1;
    };

    debuglog("skyrel answer retsock: 0x%08X\n",retsock);

    return 1;
}


unsigned int skyrel_answer_ack(int last_recv_num) {
    int resp_len;
    int retcode;
    u8 confirm[0x100];
    u32 confirm_len=0;

    int DEBUG_LEVEL = 100;

    retcode=make_tcp_pkt_confirm(last_recv_num, (char *)confirm, &confirm_len);
    if (retcode==-1) {
        if (DEBUG_LEVEL>=100) debuglog("build pkt fail confirm\n");
        return -1;
    };

    // pkt send confirm
    resp_len=tcp_talk_send(confirm, confirm_len);
    if (resp_len<0) {
        if (DEBUG_LEVEL>=100) debuglog("pkt skyrel answer ack, socket error\n");
        tcp_talk_deinit();
        return -1;
    };

    return 0;
};
