//
//tcp communication
//

#include<stdio.h>

#include <winsock.h>  

#include "skype/skype_basics.h"
#include "skype/skype_rc4.h"

#include "short_types.h"

extern RC4_context rc4_send;
extern RC4_context rc4_recv;


extern int encode_to_7bit(char *buf, uint word, int limit);
extern int first_bytes_header(u16 seqnum, char *header, int header_len, char *buf, int buf_len);
extern int first_bytes_header2(u16 seqnum, char *header, int header_len, char *buf, int buf_len);
extern int first_bytes_size(u16 seqnum, char *header, int header_len, char *buf, int buf_len);

extern int main_unpack_test (u8 *indata, u32 inlen, u32 test_type, u32 test_id);
extern int main_unpack_saveip (u8 *indata, u32 inlen);
extern int main_unpack (u8 *indata, u32 inlen);
extern int main_pack (skype_thing *mythings, int mythings_len, u8 *outdata, u32 maxlen);

extern unsigned int Calculate_CRC32(char *crc32, int bytes);
extern int tcp_talk(char *remoteip, unsigned short remoteport, char *buf, int len, char *result,int need_close);
extern int show_memory(char *mem, int len, char *text);





///////////////////////////////
//tcp second packet
////////////////////////////////
int make_tcp_pkt2(u16 seqnum, u32 rnd, char *pkt, int *pkt_len) {
    int len;
    u8 result[0x1000];
    int result_len;

    u8 send_probe_pkt[]="\x1A\xFF\xFF\x08\xCA\x04\xFF\xFF\x42\x6A\xC6\x22\xA5\x7B";

    // our session id
    /*
    skype_thing mythings[] = {
        {0, 3, 0x6519, 0},
    };
    int mythings_len = 1;
    */

    skype_thing mythings[] = {
        {0, 3, 0xB66F, 0},
    };
    int mythings_len = 1;

    skype_list      list = {&list, mythings, mythings_len, mythings_len};

    result_len = main_pack_into(&list, result, sizeof(result)-1);

    show_memory(result, result_len, "packed42:");

    main_unpack42(result, result_len);

    memcpy(send_probe_pkt+8, result, result_len);

    len=sizeof(send_probe_pkt)-1;

    //seqnum=0x2ADD;

    seqnum=_bswap16(seqnum);
    memcpy(send_probe_pkt+1,(char *)&seqnum,2);
    seqnum=_bswap16(seqnum);

    seqnum--;
    seqnum=_bswap16(seqnum);
    memcpy(send_probe_pkt+6,(char *)&seqnum,2);
    seqnum=_bswap16(seqnum);
    seqnum++;

    memcpy(pkt,send_probe_pkt,len);

    show_memory(pkt, len, "Before RC4 encrypt");
    RC4_crypt (pkt, len, &rc4_send, 0);
    show_memory(pkt, len, "After RC4 encrypt");

    show_memory(pkt,len,"send pkt2:");

    *pkt_len=len;

    return 0;
};


int process_tcp_pkt2(char *pkt, int pkt_len, int *conn_id) {
    int ret;

    show_memory(pkt,pkt_len,"result2:");

    show_memory(pkt, pkt_len, "Before RC4 decrypt");
    RC4_crypt (pkt, pkt_len, &rc4_recv, 0);
    show_memory(pkt, pkt_len, "After RC4 decrypt");

    // supernode check
    // if yet 06 0x21 blob, this is supernode reply

    if (memcmp(pkt+3,"\x04\x03",2)==0) {
        debuglog("Got 04 03 error code, relay request declined.\n");
        debuglog("(skype uptime too small, need at least 15 min)\n");
        return -1;
    };

    ret=main_unpack42(pkt, pkt_len);

    get_00_03_blob(pkt, pkt_len, conn_id);
    
    return 0;
};


int process_tcp_pkt3(char *pkt, int pkt_len, int *last_recv_pkt_num) {
    int ret;

    show_memory(pkt,pkt_len,"result3:");
    
    show_memory(pkt, pkt_len, "Before RC4 decrypt");
    RC4_crypt (pkt, pkt_len, &rc4_recv, 0);
    show_memory(pkt, pkt_len, "After RC4 decrypt");

    memcpy(last_recv_pkt_num, pkt+1, 2);

    // supernode check
    // if yet 06 0x21 blob, this is supernode reply
    ret=main_unpack42(pkt, pkt_len);
    
    return 0;
};



///////////////////////////////
//tcp confirm packet
////////////////////////////////
int make_tcp_pkt_confirm(int last_recv_num, char *pkt, int *pkt_len) {
    int len;
    u8 confirm[]="\x07\x01\xFF\xFF";

    len=sizeof(confirm)-1;  
    memcpy(confirm+2,&last_recv_num,2);
    show_memory(confirm,4,"confirm bef:");

    memcpy(pkt,confirm,len);

    RC4_crypt(pkt, len, &rc4_send, 0);
    
    show_memory(pkt,len,"send pkt confirm:");

    *pkt_len=len;

    return 0;
};


int process_tcp_pkt_after_answer(char *pkt, int pkt_len) {
    int ret;

    show_memory(pkt,pkt_len,"result2:");

    show_memory(pkt, pkt_len, "Before RC4 decrypt");
    RC4_crypt (pkt, pkt_len, &rc4_recv, 0);
    show_memory(pkt, pkt_len, "After RC4 decrypt");

    process_recv_data(pkt, pkt_len);

    //ret=main_unpack42(pkt, pkt_len);

    return 0;
};
