//
//udp communication
//

#include<stdio.h>

#include <winsock.h>  

#include "skype/skype_basics.h"
#include "skype/skype_rc4.h"


extern unsigned int Calculate_CRC32(char *crc32, int bytes);

extern int show_memory(char *mem, int len, char *text);
extern int main_unpack (u8 *indata, u32 inlen);
extern int main_unpack_once (u8 *indata, u32 inlen);

extern unsigned int global_connid;
extern char *global_connectip;
extern unsigned short global_connectport;

extern unsigned int BLOB_1_9_size;
extern unsigned int BLOB_1_9_ptr;


extern int main_pack(skype_thing *mythings, int mythings_len, u8 *outdata, u32 maxlen);
extern int main_pack_into(skype_list *list, u8 *outdata, u32 maxlen);
extern int encode_to_7bit(char *buf, unsigned int word, int limit);

#define byte(x,n)           (*(u8*)(((u8*)(x))+(n)))
#define word(x,n)           (*(u16*)(((u8*)(x))+(n)))
#define dword(x,n)          (*(u32*)(((u8*)(x))+(n)))
#define qword(x,n)          (*(u64*)(((u8*)(x))+(n)))




int make_udprelay_pkt1_prepare(u16 seqnum, char *send_pkt, int *s_len) {
    int ret=0;
    u8 result[0x1000];
    int result_len;
    u8 header[0x100];
    int header_len=5;
    int send_len;

    skype_thing    mythings[] = {
                {00, 0x12, 0x10, 0x00},
                {00, 0x13, 0x06, 0x00},
                {00, 0x13, 0x07, 0x00},
                {00, 0x13, 0x08, 0x00},
                {00, 0x13, 0x05, 0x00},
                {00, 0x13, 0x00, 0x00},
                {00, 0x13, 0x04, 0x00},
                {00, 0x13, 0x0A, 0x00},
                {00, 0x13, 0x21, 0x00},
                {00, 0x14, 0x01, 0x00},
                {00, 0x14, 0x01, 0x00},
                {00, 0x14, 0x01, 0x00},
                {00, 0x14, 0xC8, 0x00},
                {00, 0x14, 0x07, 0x00},
                {00, 0x14, 0x14, 0x00},
                {00, 0x14, 0x5A, 0x00},
                {00, 0x14, 0x01, 0x00},
    };
    int mythings_len=sizeof(mythings) / sizeof(skype_thing);

    skype_list     list = {&list, mythings, mythings_len, mythings_len};
    

    result_len=main_pack_into(&list, result, sizeof(result)-1 );
    show_memory(result, result_len, "packed42:");


    main_unpack42(result, result_len);


    header_len=encode_to_7bit(header, result_len+2, header_len);
    if (header_len==-1){
        return -1;
    };

    // pkt size
    send_len=0;
    memcpy(send_pkt+send_len,header,header_len);
    send_len+=header_len;

    // cmd 
    send_pkt[send_len]=(char )0xE2;
    send_len++;
    send_pkt[send_len]=(char )0x02;
    send_len++;

    // seqnum
    seqnum=_bswap16(seqnum);
    memcpy(send_pkt+send_len,(char *)&seqnum,2);
    seqnum=_bswap16(seqnum);
    send_len+=2;

    // 42 data
    memcpy(send_pkt+send_len,result,result_len);
    send_len+=result_len;

    show_memory(send_pkt,send_len,"push prepare pkt");

    *s_len=send_len;

    return 0;

};


int make_udprelay_pkt1(char *ourip,char *destip, u16 seqnum, u32 rnd, char *pkt, int *pkt_len) {
    RC4_context rc4;

    u8 send_pkt[0x1000];
    int send_len;
    int slen;

    u16 seqnum42;

    u32 newrnd, iv, iv3[3];
    u32 targetip;
    u32 publicip;
    u32 pkt_crc32;
    int ret;
    
    
    send_len=0;

    seqnum42=seqnum;
    ret=make_udprelay_pkt1_prepare(seqnum42, (char *)&send_pkt+send_len, &slen);
    if (ret==-1){
        //debuglog("prepare failed\n");
        return -1;
    };
    send_len+=slen;


    // make rc4 init
    targetip=inet_addr(destip);
    publicip=inet_addr(ourip);
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


/*
{
00-00: 02 00 00 00
04-01: 27 bytes
0000: 95 DB EB B2 72 3D 9C 93 01 C0 A8 01 66 D0 82 D5 | ....r=......f... |
0010: C7 B3 90 9C 42 57 4F 5A 13 D0 82                | ....BWOZ...      |
00-02: 43 00 00 00
05-03: {

--list2---
03-00: "ilovekisa"
04-01: 27 bytes
0000: 9C CB 4F AB 1F A6 A3 68 01 C0 A8 01 87 38 4A 40 | ..O....h.....8J@ |
0010: 04 17 99 9C 47 5F 34 ED EE 38 4A                | ....G_4..8J      |

00-03: B6 6F 00 00
05-07: {
00-03: 1D 6F 00 00
02-08: 109.193.94.94:9477
00-10: 1E 00 00 00
}
05-07: {
00-03: DE 78 00 00
02-08: 109.191.6.102:46866
00-10: 1A 00 00 00
}
01-09: EB 98 38 F3 4D B0 30 3E
00-18: 01 00 00 00
00-1B: 06 00 00 00
00-25: 08 00 00 00
00-26: 01 00 00 00
00-29: 04 00 00 00
00-2A: 34 00 00 00
03-2B: "0/6.16.0.10//"
04-2C: 27 bytes
0000: 95 DB EB B2 72 3D 9C 93 01 C0 A8 01 66 D0 82 D5 | ....r=......f... |
0010: C7 B3 90 9C 42 57 4F 5A 13 D0 82                | ....BWOZ...      |

01-2D: D3 E0 15 6D 17 1E 72 B9
}
--end of list2---

00-04: 1C 00 00 00
00-07: 01 00 00 00
}

*/

////////////////////////
// udp push prepare //
////////////////////////
int make_udprelay_pkt3_prepare(u16 seqnum, char *send_pkt, int *s_len) {
    int ret=0;
    u8 result[0x1000];
    int result_len;
    u8 header[0x100];
    int header_len=5;
    int send_len;

    u8 original[]=
"\x42\x2D\x40\x91\xA7\x6F\xC6\xB2\x48\x5A"
"\x10\x43\xF9\x77\x6B\x2C\xF0\x7B\xBC\x62\x2F\x30\x1D\xEA\x7D\x6D"
"\x9B\xA7\x3E\xE7\x47\x4A\x58\xEA\xEF\x91\x18\x71\x19\xEF\xBD\x5A"
"\x9B\x0E\x23\xC9\x09\x32\x0E\xCA\x4B\xE5\xD2\x9E\x3C\xD6\x21\x09"
"\x05\xAF\xF3\xD0\xFF\x01\x9E\x95\xDB\xEB\xB2\x72\x3D\x9C\x93\x01"
"\xC0\xA8\x01\x66\xD0\x82\xD5\xC7\xB3\x90\x9C\x42\x57\x4F\x5A\x13"
"\xD0\x82\x9C\xCB\x4F\xAB\x1F\xA6\xA3\x68\x01\xC0\xA8\x01\x87\x38"
"\x4A\x40\x04\x17\x99\x9C\x47\x5F\x34\xED\xEE\x38\x4A\x5E\x5E\xC1"
"\x6D\x05\x25\x66\x06\xBF\x6D\x12\xB7\xEB\x98\x38\xF3\x4D\xB0\x30"
"\x3E\x95\xDB\xEB\xB2\x72\x3D\x9C\x93\x01\xC0\xA8\x01\x66\xD0\x82"
"\xD5\xC7\xB3\x90\x9C\x42\x57\x4F\x5A\x13\xD0\x82\xD3\xE0\x15\x6D"
"\x17\x1E\x72\xB9"
;
    u32 original_len=sizeof(original)-1;


    u8 req_user[]="ilovekisa";
    //u8 req_user[]="axmtar";
    //u8 req_user[]="ellie1781";
    //u8 req_user[]="themagicforyou";
    //u8 req_user[]="xot_iam";

    u8 req_version[]="0/6.16.0.10//";

    // ilovekisa vcard  (remote vcard)
    u8 remote_vcard[]=
"\x95\xDB\xEB\xB2\x72\x3D\x9C\x93\x01\xC0\xA8\x01\x66\xD0\x82\xD5"
"\xC7\xB3\x90\x9C\x42\x57\x4F\x5A\x13\xD0\x82"
;
    u32 remote_vcard_len=sizeof(remote_vcard)-1;

    // themagicforyou card (my vcard)
    u8 INIT_UNK[]=
"\x9C\xCB\x4F\xAB\x1F\xA6\xA3\x68\x01\xC0\xA8\x01\x87\x38\x4A\x40"
"\x04\x17\x99\x9C\x47\x5F\x34\xED\xEE\x38\x4A"
;
    u32 INIT_UNK_len=sizeof(INIT_UNK)-1;

    u8 rnd64bit_[]="\x33\x50\x82\x48\xF9\xF9\xA4\x59";

    //u32 rnd64bit_1=0xF33898EB;
    //u32 rnd64bit_2=0x3E30B04D;

    // from my setup 43 41 pkt // blob1.c
    u32 rnd64bit_1=BLOB_1_9_ptr;
    u32 rnd64bit_2=BLOB_1_9_size;

    //u32 newrnd64bit_1=0x6D15E0D3;
    //u32 newrnd64bit_2=0xB9721E17;

    // from my setup 43 41 pkt // blob1.c
    u32 newrnd64bit_1=0x33FFE8A6;
    u32 newrnd64bit_2=0xCB63DD4C;

    u32 ip1;
    u32 port1;
    u32 ip2;
    u32 port2;

    skype_thing mythings3[] = {
        {00, 0x03, 0x78DE, 0x00},
        {02, 0x08, 0xFF,  0xFF},
        {00, 0x10, 0x1A, 0x00},
    };
    int mythings3_len=3;
    skype_list      list3 = {&list3, mythings3, mythings3_len, mythings3_len};

    skype_thing mythings2[] = {
        {00, 0x03, 0x6F1D, 0x00},
        {02, 0x08, 0xFF,  0xFF},
        {00, 0x10, 0x1E, 0x00},
    };
    int mythings2_len=3;
    skype_list      list2 = {&list2, mythings2, mythings2_len, mythings2_len};

    // 6519 -- out session id which sended in skyrel2
    skype_thing mythings1[] = {
        {03, 0x00, (u32 )req_user, 0x00},
        {04, 0x01, (u32 )INIT_UNK, INIT_UNK_len},
        {00, 0x03, 0x6FB6, 0x00},
        {05, 0x07, (u32 )&list2, 0x00},
//        {05, 0x07, (u32 )&list3, 0x00},
        {01, 0x09, rnd64bit_1, rnd64bit_2},
        {00, 0x18, 0x01, 0x00},
        {00, 0x1B, 0x06, 0x00},
        {00, 0x25, 0x08, 0x00},
        {00, 0x26, 0x01, 0x00},
        {00, 0x29, 0x04, 0x00},
        {00, 0x2A, 0x34, 0x00},
        {03, 0x2B, (u32 )req_version, 0x00},
        {04, 0x2C, (u32 )remote_vcard, remote_vcard_len},
        {01, 0x2D, newrnd64bit_1, newrnd64bit_2},
    };
    int mythings1_len=sizeof(mythings1) / sizeof(skype_thing);

    skype_list      list1 = {&list1, mythings1, mythings1_len, mythings1_len};

    // embedded into
    skype_thing mythings[] = {
        {00, 0x00, 0x02, 0x00},
        {04, 0x01, (u32 )remote_vcard, remote_vcard_len},
        {00, 0x02, 0x43, 0x00},
        {05, 0x03, (u32 )&list1, 0x00},
        {00, 0x04, 0x1C, 0x00},
        {00, 0x07, 0x01, 0x00},
    };
    int mythings_len=6;

    skype_list      list = {&list, mythings, mythings_len, mythings_len};
    

    ip1 = inet_addr(global_connectip);
    port1 = global_connectport;

    mythings2[0].m=global_connid;
    mythings2[1].m=htonl(ip1);
    mythings2[1].n=port1;


    /*
    ip2=inet_addr("109.191.6.102");
    port2=atoi("46866");
    //mythings3[0].m=global_connid;
    mythings3[1].m=htonl(ip2);
    mythings3[1].n=port2;
    */

    result_len=main_pack_into(&list, result, sizeof(result)-1 );
    show_memory(result, result_len, "packed42:");

    /*
    result_len = original_len;
    memcpy(result, original, result_len);
    */

    /*
    show_memory(original, original_len, "original:");
    if ( memcmp(result, original, original_len) == 0) {
        debuglog("Buffers match!\n");
    };
    */

    main_unpack42(result, result_len);


    header_len=encode_to_7bit(header, result_len+2, header_len);
    if (header_len==-1){
        return -1;
    };

    // pkt size
    send_len=0;
    memcpy(send_pkt+send_len,header,header_len);
    send_len+=header_len;

    // cmd 
    send_pkt[send_len]=(char )0xAA;
    send_len++;
    send_pkt[send_len]=(char )0x03;
    send_len++;

    // seqnum
    seqnum=_bswap16(seqnum);
    memcpy(send_pkt+send_len,(char *)&seqnum,2);
    seqnum=_bswap16(seqnum);
    send_len+=2;

    // 42 data
    memcpy(send_pkt+send_len,result,result_len);
    send_len+=result_len;

    show_memory(send_pkt,send_len,"push prepare pkt");

    *s_len=send_len;

    return 0;
};


/*

//
// prepare2
//

===
{
00-00: 02 00 00 00
04-01: 27 bytes
0000: FD 3C 33 91 1F D5 0E BD 01 C0 A8 01 64 39 FE 6F | .<3.........d9.o |
0010: DD 4D 9D 9C 58 25 9D D9 7C 39 FE                | .M..X%..|9.      |

00-02: 43 00 00 00
05-03: {
03-00: "lilith_work"
04-01: 27 bytes
0000: 9C CB 4F AB 1F A6 A3 68 01 C0 A8 01 87 38 4A 40 | ..O....h.....8J@ |
0010: 04 17 99 9C 47 3E A5 11 77 38 4A                | ....G>..w8J      |

00-03: 3E 4D 00 00
05-07: {
00-03: A7 0F 00 00
02-08: 31.169.127.145:34247
00-10: 1A 00 00 00
}
05-07: {
00-03: 79 7C 00 00
02-08: 83.139.171.65:19906
00-10: 1A 00 00 00
}
01-09: 26 42 A6 1B 15 2B 19 7E
00-18: 01 00 00 00
00-1B: 06 00 00 00
00-25: 08 00 00 00
00-26: 01 00 00 00
00-29: 04 00 00 00
00-2A: 34 00 00 00
03-2B: "0/6.16.0.10//"
04-2C: 27 bytes
0000: FD 3C 33 91 1F D5 0E BD 01 C0 A8 01 64 39 FE 6F | .<3.........d9.o |
0010: DD 4D 9D 9C 58 25 9D D9 7C 39 FE                | .M..X%..|9.      |

01-2D: DF FB 20 9C AE 94 8B BC
01-2E: 76 80 EC 68 3D 05 97 03
}
00-04: 1C 00 00 00
00-07: 01 00 00 00
}
===
*/


////////////////////////
// udp push prepare2  //
////////////////////////
int make_udprelay_pkt3_prepare2(u16 seqnum, char *send_pkt, int *s_len) {
    int ret=0;
    u8 result[0x1000];
    int result_len;
    u8 header[0x100];
    int header_len=5;
    int send_len;

    int my_connid_to_relay = 0x6FB6;

    u8 req_user[]="lilith_work";

    u8 req_version[]="0/6.16.0.10//";

    // lilith_work vcard (remote vcard)
    u8 remote_vcard[]=
"\xFD\x3C\x33\x91\x1F\xD5\x0E\xBD\x01\xC0\xA8\x01\x64\x39\xFE\x6F"
"\xDD\x4D\x9D\x9C\x58\x25\x9D\xD9\x7C\x39\xFE"
;
    u32 remote_vcard_len=sizeof(remote_vcard)-1;

    // themagicforyou card (my vcard)
    u8 INIT_UNK[]=
"\x9C\xCB\x4F\xAB\x1F\xA6\xA3\x68\x01\xC0\xA8\x01\x87\x38\x4A\x40"
"\x04\x17\x99\x9C\x47\x3E\xA5\x11\x77\x38\x4A"
;
    u32 INIT_UNK_len=sizeof(INIT_UNK)-1;

    u8 rnd64bit_[]="\x33\x50\x82\x48\xF9\xF9\xA4\x59";

    u32 rnd64bit_1=0xF33898EB;
    u32 rnd64bit_2=0x3E30B04D;

    u32 newrnd64bit_1=0x6D15E0D3;
    u32 newrnd64bit_2=0xB9721E17;

    u32 ip1;
    u32 port1;
    u32 ip2;
    u32 port2;

    skype_thing mythings2[] = {
        {00, 0x03, 0x6F1D, 0x00},
        {02, 0x08, 0xFF,  0xFF},
        {00, 0x10, 0x1E, 0x00},
    };
    int mythings2_len=3;
    skype_list      list2 = {&list2, mythings2, mythings2_len, mythings2_len};

    // important 6FB6 -- out session id which sended in skyrel2
    skype_thing mythings1[] = {
        {03, 0x00, (u32 )req_user, 0x00},
        {04, 0x01, (u32 )INIT_UNK, INIT_UNK_len},
        //{00, 0x03, 0x6FB6, 0x00},     
        {00, 0x03, my_connid_to_relay, 0x00},
        {05, 0x07, (u32 )&list2, 0x00},
        {01, 0x09, rnd64bit_1, rnd64bit_2},
        {00, 0x18, 0x01, 0x00},
        {00, 0x1B, 0x06, 0x00},
        {00, 0x25, 0x08, 0x00},
        {00, 0x26, 0x01, 0x00},
        {00, 0x29, 0x04, 0x00},
        {00, 0x2A, 0x34, 0x00},
        {03, 0x2B, (u32 )req_version, 0x00},
        {04, 0x2C, (u32 )remote_vcard, remote_vcard_len},
        {01, 0x2D, newrnd64bit_1, newrnd64bit_2},
    };
    int mythings1_len=sizeof(mythings1) / sizeof(skype_thing);

    skype_list      list1 = {&list1, mythings1, mythings1_len, mythings1_len};

    // embedded into
    skype_thing mythings[] = {
        {00, 0x00, 0x02, 0x00},
        {04, 0x01, (u32 )remote_vcard, remote_vcard_len},
        {00, 0x02, 0x43, 0x00},
        {05, 0x03, (u32 )&list1, 0x00},
        {00, 0x04, 0x1C, 0x00},
        {00, 0x07, 0x01, 0x00},
    };
    int mythings_len=6;

    skype_list      list = {&list, mythings, mythings_len, mythings_len};
    

    ip1 = inet_addr(global_connectip);
    port1 = global_connectport;

    mythings2[0].m=global_connid;
    mythings2[1].m=htonl(ip1);
    mythings2[1].n=port1;


    result_len=main_pack_into(&list, result, sizeof(result)-1 );
    show_memory(result, result_len, "packed42:");

    main_unpack42(result, result_len);

    header_len=encode_to_7bit(header, result_len+2, header_len);
    if (header_len==-1){
        return -1;
    };

    // pkt size
    send_len=0;
    memcpy(send_pkt+send_len,header,header_len);
    send_len+=header_len;

    // cmd 
    send_pkt[send_len]=(char )0xAA;
    send_len++;
    send_pkt[send_len]=(char )0x03;
    send_len++;

    // seqnum
    seqnum=_bswap16(seqnum);
    memcpy(send_pkt+send_len,(char *)&seqnum,2);
    seqnum=_bswap16(seqnum);
    send_len+=2;

    // 42 data
    memcpy(send_pkt+send_len,result,result_len);
    send_len+=result_len;

    show_memory(send_pkt,send_len,"push prepare pkt");

    *s_len=send_len;

    return 0;
};


/*

// prepare3

===
{
00-00: 02 00 00 00
04-01: 27 bytes
0000: EB 69 39 38 17 62 21 74 01 C0 A8 B2 1B 88 3D 40 | .i98.b!t......=@ |
0010: 04 17 A9 9C 51 2E 3B A6 F1 88 3D                | ....Q.;...=      |

00-02: 43 00 00 00
05-03: {
03-00: "ellie1781"
04-01: 27 bytes
0000: 9C CB 4F AB 1F A6 A3 68 01 C0 A8 01 87 38 4A 40 | ..O....h.....8J@ |
0010: 04 17 99 9C 47 3E A5 11 77 38 4A                | ....G>..w8J      |

00-03: 14 23 00 00
05-07: {
00-03: 29 7E 00 00
02-08: 83.139.171.65:19906
00-10: 1A 00 00 00
}
05-07: {
00-03: FC 70 00 00
02-08: 93.81.229.168:27566
00-10: 1A 00 00 00
}
01-09: D4 D7 45 9D 00 A9 31 3D
00-18: 01 00 00 00
00-1B: 06 00 00 00
00-26: 01 00 00 00
00-29: 04 00 00 00
00-2A: 34 00 00 00
03-2B: "0/6.16.0.10//"
04-2C: 27 bytes
0000: EB 69 39 38 17 62 21 74 01 C0 A8 B2 1B 88 3D 40 | .i98.b!t......=@ |
0010: 04 17 A9 9C 51 2E 3B A6 F1 88 3D                | ....Q.;...=      |

01-2D: E0 D2 09 57 77 68 7A 42
01-2E: A0 FC A9 5A 08 05 69 92
}
00-04: 1C 00 00 00
00-07: 01 00 00 00
}
===

*/

int make_udprelay_pkt3_prepare3(u16 seqnum, char *send_pkt, int *s_len) {
    int ret=0;
    u8 result[0x1000];
    int result_len;
    u8 header[0x100];
    int header_len=5;
    int send_len;

    int my_connid_to_relay = 0x6FB6;

    u8 req_user[]="ellie1781";

    u8 req_version[]="0/6.16.0.10//";

    //
    // only 8 bytes change, fail to connect, "user offline"
    //

    u8 remote_vcard[]=
"\xEB\x69\x39\x38\x17\x62\x21\x74\x01\xC0\xA8\xB2\x1B\x88\x3D\x40"
"\x04\x17\xA9\x9C\x51\x2E\x3B\xA6\xF1\x88\x3D"
;

    u32 remote_vcard_len=sizeof(remote_vcard)-1;

    // local vcard (my vcard)
    u8 INIT_UNK[]=
"\x9C\xCB\x4F\xAB\x1F\xA6\xA3\x68\x01\xC0\xA8\x01\x87\x38\x4A\x40"
"\x04\x17\x99\x9C\x47\x3E\xA5\x11\x77\x38\x4A"
;

    u32 INIT_UNK_len=sizeof(INIT_UNK)-1;

    u8 rnd64bit_[]="\x33\x50\x82\x48\xF9\xF9\xA4\x59";

    u32 rnd64bit_1=0xF33898EB;
    u32 rnd64bit_2=0x3E30B04D;

    u32 newrnd64bit_1=0x6D15E0D3;
    u32 newrnd64bit_2=0xB9721E17;

    u32 ip1;
    u32 port1;
    u32 ip2;
    u32 port2;

    skype_thing mythings2[] = {
        {00, 0x03, 0x6F1D, 0x00},
        {02, 0x08, 0xFF,  0xFF},
        {00, 0x10, 0x1E, 0x00},
    };
    int mythings2_len=3;
    skype_list      list2 = {&list2, mythings2, mythings2_len, mythings2_len};

    // important 6FB6 -- out session id which sended in skyrel2
    skype_thing mythings1[] = {
        {03, 0x00, (u32 )req_user, 0x00},
        {04, 0x01, (u32 )INIT_UNK, INIT_UNK_len},
        //{00, 0x03, 0x6FB6, 0x00},     
        {00, 0x03, my_connid_to_relay, 0x00},
        {05, 0x07, (u32 )&list2, 0x00},
        {01, 0x09, rnd64bit_1, rnd64bit_2},
        {00, 0x18, 0x01, 0x00},
        {00, 0x1B, 0x06, 0x00},
        {00, 0x25, 0x08, 0x00},
        {00, 0x26, 0x01, 0x00},
        {00, 0x29, 0x04, 0x00},
        {00, 0x2A, 0x34, 0x00},
        {03, 0x2B, (u32 )req_version, 0x00},
        {04, 0x2C, (u32 )remote_vcard, remote_vcard_len},
        {01, 0x2D, newrnd64bit_1, newrnd64bit_2},
    };
    int mythings1_len=sizeof(mythings1) / sizeof(skype_thing);

    skype_list      list1 = {&list1, mythings1, mythings1_len, mythings1_len};

    // embedded into
    skype_thing mythings[] = {
        {00, 0x00, 0x02, 0x00},
        {04, 0x01, (u32 )remote_vcard, remote_vcard_len},
        {00, 0x02, 0x43, 0x00},
        {05, 0x03, (u32 )&list1, 0x00},
        {00, 0x04, 0x1C, 0x00},
        {00, 0x07, 0x01, 0x00},
    };
    int mythings_len=6;

    skype_list      list = {&list, mythings, mythings_len, mythings_len};
    

    ip1 = inet_addr(global_connectip);
    port1 = global_connectport;

    mythings2[0].m=global_connid;
    mythings2[1].m=htonl(ip1);
    mythings2[1].n=port1;


    result_len=main_pack_into(&list, result, sizeof(result)-1 );
    show_memory(result, result_len, "packed42:");

    main_unpack42(result, result_len);

    header_len=encode_to_7bit(header, result_len+2, header_len);
    if (header_len==-1){
        return -1;
    };

    // pkt size
    send_len=0;
    memcpy(send_pkt+send_len,header,header_len);
    send_len+=header_len;

    // cmd 
    send_pkt[send_len]=(char )0xAA;
    send_len++;
    send_pkt[send_len]=(char )0x03;
    send_len++;

    // seqnum
    seqnum=_bswap16(seqnum);
    memcpy(send_pkt+send_len,(char *)&seqnum,2);
    seqnum=_bswap16(seqnum);
    send_len+=2;

    // 42 data
    memcpy(send_pkt+send_len,result,result_len);
    send_len+=result_len;

    show_memory(send_pkt,send_len,"push prepare pkt");

    *s_len=send_len;

    return 0;
};


//
// prepare4
//

////////////////////////
// udp push prepare4  //
////////////////////////
int make_udprelay_pkt3_prepare4(u16 seqnum, char *remote_name, char *remote_vcard, char *send_pkt, int *s_len) {
    int ret=0;
    u8 result[0x1000];
    int result_len;
    u8 header[0x100];
    int header_len=5;
    int send_len;

    // its local connection id!
    int my_connid_to_relay = 0x6FB6;

    u8 req_version[]="0/6.16.0.10//";

    //
    // only 8 bytes change, fail to connect, "user offline"
    //

    //u32 remote_vcard_len=sizeof(remote_vcard)-1;

    // local vcard (my vcard, hostid)
/*
    u8 INIT_UNK[] = 
"\x9C\xCB\x4F\xAB\x1F\xA6\xA3\x68\x01\xC0\xA8\x01\x87\x38\x4A\x40"
"\x04\x17\x99\x9C\x47\x3E\xA5\x11\x77\x38\x4A"
;
*/
    u8 INIT_UNK[] = 
"\x9A\x9A\x9B\x9B\x1F\xA6\xA3\x68\x01\xC0\xA8\x01\x87\x38\x4A\x40"
"\x04\x17\x99\x9C\x47\x3E\xA5\x11\x77\x38\x4A"
;

    u32 INIT_UNK_len=sizeof(INIT_UNK)-1;

    u8 rnd64bit_[]="\x33\x50\x82\x48\xF9\xF9\xA4\x59";

    //u32 rnd64bit_1=0xF33898EB;
    //u32 rnd64bit_2=0x3E30B04D;

    // from my setup 43 41 pkt // blob1.c
    u32 rnd64bit_1=BLOB_1_9_ptr;
    u32 rnd64bit_2=BLOB_1_9_size;

    //u32 newrnd64bit_1=0x6D15E0D3;
    //u32 newrnd64bit_2=0xB9721E17;

    // from my setup 43 41 pkt // blob1.c
    u32 newrnd64bit_1=0x33FFE8A6;
    u32 newrnd64bit_2=0xCB63DD4C;

    u32 ip1;
    u32 port1;
    u32 ip2;
    u32 port2;

    skype_thing mythings2[] = {
        {00, 0x03, 0x6F1D, 0x00},
        {02, 0x08, 0xFF,  0xFF},
        {00, 0x10, 0x1E, 0x00},
    };
    int mythings2_len=3;
    skype_list      list2 = {&list2, mythings2, mythings2_len, mythings2_len};

    // important 6FB6 -- out session id which sended in skyrel2
    skype_thing mythings1[] = {
        {03, 0x00, (u32 )remote_name, 0x00},
        {04, 0x01, (u32 )INIT_UNK, INIT_UNK_len},
        //{00, 0x03, 0x6FB6, 0x00},     
        {00, 0x03, my_connid_to_relay, 0x00},
        {05, 0x07, (u32 )&list2, 0x00},
        {01, 0x09, rnd64bit_1, rnd64bit_2},
        {00, 0x18, 0x01, 0x00},
        {00, 0x1B, 0x06, 0x00},
        {00, 0x25, 0x08, 0x00},
        {00, 0x26, 0x01, 0x00},
        {00, 0x29, 0x04, 0x00},
        {00, 0x2A, 0x34, 0x00},
        {03, 0x2B, (u32 )req_version, 0x00},
        {04, 0x2C, (u32 )remote_vcard, 0x1B},
        {01, 0x2D, newrnd64bit_1, newrnd64bit_2},
    };
    int mythings1_len=sizeof(mythings1) / sizeof(skype_thing);

    skype_list      list1 = {&list1, mythings1, mythings1_len, mythings1_len};

    // embedded into
    skype_thing mythings[] = {
        {00, 0x00, 0x02, 0x00},
        {04, 0x01, (u32 )remote_vcard, 0x1B},
        {00, 0x02, 0x43, 0x00},
        {05, 0x03, (u32 )&list1, 0x00},
        {00, 0x04, 0x1C, 0x00},
        {00, 0x07, 0x01, 0x00},
    };
    int mythings_len=6;

    skype_list      list = {&list, mythings, mythings_len, mythings_len};
    
    // just in case
    //int remote_vcard_len = 0x1B;


    ip1 = inet_addr(global_connectip);
    port1 = global_connectport;

    mythings2[0].m=global_connid;
    mythings2[1].m=htonl(ip1);
    mythings2[1].n=port1;


    result_len=main_pack_into(&list, result, sizeof(result)-1 );
    show_memory(result, result_len, "packed42:");

    main_unpack42(result, result_len);

    header_len=encode_to_7bit(header, result_len+2, header_len);
    if (header_len==-1){
        return -1;
    };

    // pkt size
    send_len=0;
    memcpy(send_pkt+send_len,header,header_len);
    send_len+=header_len;

    // cmd 
    send_pkt[send_len]=(char )0xAA;
    send_len++;
    send_pkt[send_len]=(char )0x03;
    send_len++;

    // seqnum
    seqnum=_bswap16(seqnum);
    memcpy(send_pkt+send_len,(char *)&seqnum,2);
    seqnum=_bswap16(seqnum);
    send_len+=2;

    // 42 data
    memcpy(send_pkt+send_len,result,result_len);
    send_len+=result_len;

    show_memory(send_pkt,send_len,"push prepare pkt");

    *s_len=send_len;

    return 0;
};


////////////////////////
// udp request Search //
////////////////////////
int make_udprelay_pkt3(char *ourip, char *destip, u16 seqnum, u32 rnd, char *remote_name, char *remote_vcard, char *pkt, int *pkt_len) {
    RC4_context rc4;

    u8 send_pkt[0x1000];
    int send_len;
    int slen;

    u16 seqnum42;

    u32 newrnd, iv, iv3[3];
    u32 targetip;
    u32 publicip;
    u32 pkt_crc32;
    int ret;
    
    
    send_len=0;

    seqnum42=seqnum;
    //ret=make_udprelay_pkt3_prepare(seqnum42, (char *)&send_pkt+send_len, &slen);
    //ret=make_udprelay_pkt3_prepare2(seqnum42, (char *)&send_pkt+send_len, &slen);
    //ret=make_udprelay_pkt3_prepare3(seqnum42, (char *)&send_pkt+send_len, &slen);
    ret=make_udprelay_pkt3_prepare4(seqnum42, remote_name, remote_vcard, (char *)&send_pkt+send_len, &slen);
    if (ret==-1){
        //debuglog("prepare failed\n");
        return -1;
    };
    send_len+=slen;


    // make rc4 init
    targetip=inet_addr(destip);
    publicip=inet_addr(ourip);
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


int process_udprelay_pkt1(char *pkt,int pkt_len,char *ourip,char *destip) {
    RC4_context rc4;
    u32 newrnd;
    u32 targetip;
    u32 publicip;
    u32 iv3[3];
    u32 iv;
    int header_len;


    show_memory(pkt, pkt_len, "result len:");

    targetip=inet_addr(destip);
    publicip=inet_addr(ourip);

    newrnd = _bswap32(dword(pkt+3,0));

    iv3[2] = _bswap16(word(pkt,0)); 
    iv3[1] = _bswap32(publicip);
    iv3[0] = _bswap32(targetip);

    iv = crc32(iv3,3) ^ newrnd;

    Skype_RC4_Expand_IV_udp (&rc4, iv, 1);

    header_len=11;

    show_memory(pkt+header_len, pkt_len-header_len, "bef rc4:");  
    RC4_crypt (pkt+header_len, pkt_len-header_len, &rc4, 0);
    show_memory(pkt+header_len, pkt_len-header_len, "aft rc4:");  

    // +6 for data efore 41/42
    main_unpack(pkt+header_len+6,pkt_len-header_len);

    get_02_11_blob(pkt+header_len+6,pkt_len-header_len);

    if (pkt_len < 0x100) {
        debuglog("returning size too small\n");
    };
    if (pkt_len == 0x0B) {
        debuglog("Error. RC4 decoding fail on remote side.\n");
        debuglog("--- Check you public ip addr!!! ---\n");
    };
    if (pkt_len == 0x11) {
        debuglog("Get error code (42 unpack error?)\n");
    };
    if (pkt_len == 0x12) {
        debuglog("Success!\n");
    };

    if (memcmp(pkt+header_len,"\x04\x03",2)==0) {
        debuglog("Got 04 03 error code (some unknown)\n");
    };

    if (memcmp(pkt+header_len,"\x04\xB3\x04",3)==0) {
        debuglog("Got B3 04 code. Success!\n");
    };

    return 0;
};


int process_udprelay_pkt3(char *pkt,int pkt_len,char *ourip,char *destip) {
    RC4_context rc4;
    u32 newrnd;
    u32 targetip;
    u32 publicip;
    u32 iv3[3];
    u32 iv;
    int header_len;


    show_memory(pkt, pkt_len, "result len:");

    targetip=inet_addr(destip);
    publicip=inet_addr(ourip);

    newrnd = _bswap32(dword(pkt+3,0));

    iv3[2] = _bswap16(word(pkt,0)); 
    iv3[1] = _bswap32(publicip);
    iv3[0] = _bswap32(targetip);

    iv = crc32(iv3,3) ^ newrnd;

    Skype_RC4_Expand_IV_udp (&rc4, iv, 1);

    header_len=11;

    show_memory(pkt+header_len,pkt_len-header_len,"bef rc4:");  
    RC4_crypt (pkt+header_len, pkt_len-header_len, &rc4, 0);
    show_memory(pkt+header_len,pkt_len-header_len,"aft rc4:");  

    //+5 for in rc4 data before 41
    main_unpack(pkt+header_len+5,pkt_len-header_len-5);

    if (pkt_len == 0x0B) {
        debuglog("Error. RC4 decoding fail on remote side.\n");
        debuglog("--- Check you public ip addr!!! ---\n");
    };
    if (pkt_len == 0x11) {
        debuglog("Get error code (42 unpack error?)\n");
    };
    if (pkt_len == 0x12) {
        debuglog("Success!\n");
    };

    if (memcmp(pkt+header_len,"\x04\xB3\x04",3)==0) {
        debuglog("Got B3 04 code. Success!\n");
    };


    if (memcmp(pkt+header_len,"\x04\x03",2)==0) {
        debuglog("Got 04 03 error code (some unknown)\n");
        return -1;
    };

    /*
    {
        00-06: 03 00 00 00
    }
    */
    if (memcmp(pkt+header_len,"\x07\xB3\x03",3)==0) {
        debuglog("Got B3 03 code. User offline or wrong supernode.\n");
        debuglog("(or connect on real ip in vcard failed?).\n");
        return -1;
    };
    if (memcmp(pkt+header_len,"\x04\xD3\x05",3)==0) {
        debuglog("Got D3 05 code. Some error. User vcard mismatch.\n");
        return -1;
    };
    if (memcmp(pkt+header_len,"\x07\xDB\x05",3)==0) {
        debuglog("Got DB 05 code. Some error.\n");
        debuglog("Just too often, or ConnID too often\n");
        debuglog("Wait a bit.\n");
        return -105;
    };

    return 0;
};

