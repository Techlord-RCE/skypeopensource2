//
//udp communication
//

#include <stdio.h>

#include "skype/skype_basics.h"
#include "skype/skype_rc4.h"


extern unsigned int Calculate_CRC32(char *crc32, int bytes);

extern int show_memory(char *mem, int len, char *text);
extern int main_unpack (u8 *indata, u32 inlen);
extern int main_unpack_once (u8 *indata, u32 inlen);


extern u8 bigbuf[0x100000];
extern u32 bigbuf_count;

extern int main_pack(skype_thing *mythings, int mythings_len, u8 *outdata, u32 maxlen);
extern int main_pack_into(skype_list *list, u8 *outdata, u32 maxlen);
extern int encode_to_7bit(char *buf, unsigned int word, int limit);

extern char MY_ADDR[0x100];


////////////////////////
// udp search prepare //
////////////////////////
int make_udp_search_prepare(char *req_user, u16 seqnum, char *send_pkt, int *s_len, int num1, int num2) {
    u8 result[0x1000];
    int result_len;
    u8 header[0x100];
    int header_len=5;
    int send_len;


    skype_thing mythings2[] = {
        {03, 00, (u32 )req_user, 0x00},
        {00, 01, 0x00, 0x00},
        {00, 02, 0x00, 0x00},
    };
    int mythings2_len=3;

    skype_list      list2 = {&list2, mythings2, mythings2_len, mythings2_len};

    u32 dw[2] = { 0x10,0x0B };
    skype_thing mythings[] = {
        {05, 00, (u32 )&list2, 0x00},
        {06, 01, (u32 )&dw, 2<<2},
    };
    int mythings_len=2;
    skype_list      list = {&list, mythings, mythings_len, mythings_len};



    mythings2[1].m=num1;
    mythings2[2].m=num2;

    result_len=main_pack_into(&list, result, sizeof(result)-1 );

    //show_memory(result,result_len,"packed42:");
    //main_unpack(result,result_len);

    header_len=encode_to_7bit(header, result_len+2, header_len);


    // pkt size
    send_len=0;
    memcpy(send_pkt+send_len,header,header_len);
    send_len+=header_len;

    // cmd 
    send_pkt[send_len]=0x72;
    send_len++;

    // seqnum
    seqnum=_bswap16(seqnum);
    memcpy(send_pkt+send_len,(char *)&seqnum,2);
    seqnum=_bswap16(seqnum);
    send_len+=2;

    // 42 data
    memcpy(send_pkt+send_len,result,result_len);
    send_len+=result_len;

    *s_len=send_len;


    return 0;

};



////////////////////////
// udp request Search //
////////////////////////
int make_udp_reqsearch_pkt1(char *destip, u16 seqnum, u32 rnd, char *req_user, char *pkt, int *pkt_len) {
    RC4_context rc4;

    u8 send_pkt[0x1000];
    int send_len;
    int slen;

    u16 seqnum42;

    u32 newrnd, iv, iv3[3];
    u32 targetip;
    u32 publicip;
    u32 pkt_crc32;

    //u8 req_user[]="putin";
    //u8 req_user[]="alex.gordon";
    //u8 req_user[]="alex.gordon8";
    //u8 req_user[]="alex.";
    //u8 req_user[]="shamanyst";

    
    
    send_len=0;

    seqnum42=seqnum;
    make_udp_search_prepare(req_user, seqnum42, (char *)&send_pkt+send_len, &slen, 0x00, 0x10);
    send_len+=slen;
    
    /*
    seqnum42+=12;
    make_udp_search_prepare(req_user, seqnum42, (char *)&send_pkt+send_len, &slen, 0x05, 0x10);
    send_len+=slen;

    seqnum42+=6;
    make_udp_search_prepare(req_user, seqnum42, (char *)&send_pkt+send_len, &slen, 0x09, 0x14);
    send_len+=slen;
    */

    // make rc4 init
    targetip=inet_addr(destip);
    publicip=inet_addr(MY_ADDR);
    //prepare
    newrnd = rnd;
    iv3[0] = ntohl(publicip);
    iv3[1] = ntohl(targetip);
    iv3[2] = seqnum+1;
    //init seed for rc4
    iv = crc32(iv3,3) ^ newrnd;
    //crc32
    pkt_crc32=Calculate_CRC32( (char *)send_pkt,send_len);
    //init rc4 structure by iv
    Skype_RC4_Expand_IV_udp (&rc4, iv, 1);

    
    // encode rc4
    show_memory(send_pkt,send_len,"bef rc4:");
    RC4_crypt  (send_pkt,send_len, &rc4, 0);
    show_memory(send_pkt,send_len,"aft rc4:");


    //make send pkt

    //pktnum+1,
    seqnum++;
    seqnum=_bswap16(seqnum);
    memcpy(pkt,(char*)&seqnum,2);
    seqnum=_bswap16(seqnum);

    //02 - tip dannih ?
    memcpy(pkt+2,"\x02",1);
    
    //init data//our rnd seed?
    newrnd=_bswap32(newrnd);
    memcpy(pkt+3,(char*)&newrnd,4);
    newrnd=_bswap32(newrnd);
    
    //crc32
    pkt_crc32=_bswap32(pkt_crc32);
    memcpy(pkt+7,(char *)&pkt_crc32,4);
    pkt_crc32=_bswap32(pkt_crc32);

    //rc4 data
    memcpy(pkt+11,(char *)&send_pkt,send_len);

    //display pkt bef send
    show_memory(pkt,send_len+11,"send pkt:");

    *pkt_len=send_len+11;


    return 0;
};




int process_udp_reqsearch_pkt1(char *pkt, int pkt_len, char *destip) {
    RC4_context rc4;
    u32 newrnd;
    u32 targetip;
    u32 publicip;
    u32 iv3[3];
    u32 iv;
    int flagbig;
    int header_len;

    flagbig=0;
    //if (pkt_len > 0x520) {
    //if (pkt_len > 0x500) {
    if (pkt_len > 0x530) {
        flagbig=1;
    };

    show_memory(pkt, pkt_len, "Recv data:");

    targetip=inet_addr(destip);
    publicip=inet_addr(MY_ADDR);

    if (flagbig){
        newrnd = _bswap32(dword(pkt+7, 0));
    }else{
        newrnd = _bswap32(dword(pkt+3, 0));
    };

    iv3[2] = _bswap16(word(pkt, 0)); 
    iv3[1] = _bswap32(publicip);
    iv3[0] = _bswap32(targetip);

    iv = crc32(iv3,3) ^ newrnd;

    Skype_RC4_Expand_IV_udp (&rc4, iv, 1);

    if (flagbig){
        header_len=15;
    }else{
        header_len=11;
    };

    if (pkt_len == 11) {
        printf("Some recv len error (too small).\n");
        printf("Possible our_public_ip address error.\n");

        show_memory(pkt, pkt_len, "bef rc4:");  
        RC4_crypt (pkt, pkt_len, &rc4, 0);
        show_memory(pkt, pkt_len, "aft rc4:");  
        return 0;
    };

    show_memory(pkt+header_len,pkt_len-header_len,"bef rc4:");  
    RC4_crypt (pkt+header_len, pkt_len-header_len, &rc4, 0);
    show_memory(pkt+header_len,pkt_len-header_len,"aft rc4:");  

    // need check for 00-01: 01 return
    main_unpack(pkt+header_len, pkt_len-header_len);

    memcpy(bigbuf+bigbuf_count,pkt+header_len,pkt_len-header_len);
    bigbuf_count+=pkt_len-header_len;

    return 0;
};


