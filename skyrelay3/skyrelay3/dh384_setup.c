/*  
*
* TCP connect to skype supernode
*
*/

#include "skype/skype_basics.h"
#include "skype/skype_rc4.h"

#include "short_types.h"


// rc4 obfuscation
//extern void Skype_RC4_Expand_IV (RC4_context * const rc4, const u32 iv, const u32 flags);
//extern void RC4_crypt (u8 * buffer, u32 bytes, RC4_context * const rc4, const u32 test);


// global data
RC4_context rc4_send;
RC4_context rc4_recv;

char xoteg_pub[0x80+1];
char xoteg_sec[0x80+1];
char skype_pub[0x100+1];
char remote_pubkey[0x80];

    char skype_pub[]=
"\xB8\x50\x6A\xEE\xD8\xED\x30\xFE\x1C\x0E\x67\x74\x87\x4B\x59\x20"
"\x6A\x77\x32\x90\x42\xA4\x9B\xE2\x40\x3D\xA4\x7D\x50\x05\x24\x41"
"\x06\x7F\x87\xBC\xD5\x7E\x65\x79\xB8\x3D\xF0\xBA\xDE\x2B\xEF\xF5"
"\xB5\xCD\x8D\x87\xE8\xB3\xED\xAC\x5F\x57\xFA\xBC\xCD\x49\x69\x59"
"\x74\xE2\xB5\xE5\xF0\x28\x7D\x6C\x19\xEC\xC3\x1B\x45\x04\xA9\xF8"
"\xBE\x25\xDA\x78\xFA\x4E\xF3\x45\xF9\x1D\x33\x9B\x73\xCC\x2D\x70"
"\xB3\x90\x4E\x11\xCA\x57\x0C\xE9\xB5\xDC\x4B\x08\xB3\xC4\x4B\x74"
"\xDC\x46\x35\x87\xEA\x63\x7E\xF4\x45\x6E\x61\x46\x2B\x72\x04\x2F"
"\xC2\xF4\xAD\x55\x10\xA9\x85\x0C\x06\xDC\x9A\x73\x74\x41\x2F\xCA"
"\xDD\xA9\x55\xBD\x98\x00\xF9\x75\x4C\xB3\xB8\xCC\x62\xD0\xE9\x8D"
"\x82\x82\x18\x09\x71\x05\x5B\x45\x7C\x06\xF3\x51\xE6\x11\x64\xFC"
"\x5A\x9D\xE9\xD8\x3D\x1D\x13\x78\x96\x40\x01\x38\x0B\x5B\x99\xEE"
"\x4C\x5C\x7D\x50\xAC\x24\x62\xA4\xB7\xEA\x34\xFD\x32\xD9\x0B\xD8"
"\xD4\xB4\x64\x10\x26\x36\x73\xF9\x00\xD1\xC6\x04\x70\x16\x5D\xF9"
"\xF3\xCB\x48\x01\x6A\xB8\xCA\x45\xCE\x68\x75\xA7\x1D\x97\x79\x15"
"\xCA\x82\x51\xB5\x02\x58\x74\x8D\xBC\x37\xFE\x33\x2E\xDC\x28\x55"
;


int GLOBAL_STATE_MACHINE;

extern enum { AES_KEY_INIT, AES_KEY_OK };


u8 aes_key[0x20];
u32 REMOTE_SESSION_ID;
//u32 LOCAL_SESSION_ID=0x2192;
u32 LOCAL_SESSION_ID=0x5C25;

//skype v5.5
u8 CLIENT_VERSION[0x100]="0/5.5.0.124//";

// important!!! for first stage, init session, not remove!!!
uint START_HEADER_ID = 0x16352BA9;


// global aes blkseq key
int blkseq;

extern char MY_ADDR[0x100];


extern u32 Skype_Handshake(char *out, int *n);
extern u32 Skype_Handshake2_powmod (char *input, int len, char *output, char *output2);

extern u32  supernode_iv2[13];


unsigned int showme_rc4(char *result, int len);
u32                 supernode_ivi, supernode_ivo;   // I/O IVs, probably no need to save

#define bswap16(x)          ((((x)>>8)&0xFF)+(((x)&0xFF)<<8))


static u32 decode32 (u32 * const to, const u8 * const from, const u32 bytes)
{
    u32     i, a;
    
    for (i = 0, a = 0; i < bytes; i++)
    {
        a |= (from[i] & 127) << (i*7);
        if (from[i] <= 127)
        {
            *to = a;    // length ok
            return i+1;
        }
    }
    *to = 0x80000000;   // really invalid length, ran out of input
    return i+1;
}

#define byte1(x,n)          (*(u8*)(((u8*)(x))+(n)))
#define word1(x,n)          (*(u16*)(((u8*)(x))+(n)))
#define dword1(x,n)         (*(u32*)(((u8*)(x))+(n)))
#define qword1(x,n)         (*(u64*)(((u8*)(x))+(n)))


u8 aes_key[0x20];
extern u32 Skype_Handshake(char *out, int *n);
extern u32 Skype_Handshake2_powmod (char *input, int len, char *output, char *output2);


int make_dh384_handshake(char *ip, unsigned short port){
    u8 result[0x1000];
    u8 result2[0x1000];
    u8 recvbuf[0x1000];
    u32 recvlen;
    u32 local_rnd;
    u32 remote_rnd;
    u32 iv;
    char *pkt;
    int send_len;
    int len;
    int len2;
    char *bufhash;
    char *cmphash;
    int n;
    unsigned int j_global;

    u32 buffer[64];
    u32 buffer2[64];

    int i,j;


//  u32                 supernode_iv2[13];  // common DH-384 key, probably no need to save

    u8                  *supernode_data;        // leftovers
    u32                 supernode_bytes;        // left from the last packet
    u8                  *supernode_last_data;   // position of the last returned command to be removed
    u32                 supernode_last_bytes;   // size of the last returned command with its header
    u32                 supernode_idi, supernode_ido;   // I/O packet sequence numbers

    int maxlen  = 8192;

    //memset (&supernode, 0, sizeof (supernode));   // absolutely necessary

    supernode_ivi=0;
    supernode_ivo=0;
    supernode_last_bytes=0;
    supernode_idi=0;
    supernode_ido=0;


    pkt=malloc(0x1000);

    Skype_Handshake(pkt, &send_len);
    
    printf("Handshake v5.5 1 pkt len: 0x%08X\n",send_len);

    // Display pkt before sending
    show_memory(pkt, send_len, "Send pkt");

    
    // Sending packet
    len=tcp_talk(ip, port, pkt, send_len, result, 0);
    if (len<=0) {
        printf("recv timeout\n");
        return -1;
    };
    if (len>=1023) {
        printf("Recv len: 0x%08X\n",len);
        printf("Too big pkt recv, exiting...\n");
        return -1;
    };

    // Display received pkt
    show_memory(result, len, "Result");

    bufhash=malloc(0x100);
    cmphash=malloc(0x100);
    Skype_Handshake2_powmod(result, len, bufhash, cmphash);

    show_memory(bufhash, 8, "MD5 SEND Hash");
    show_memory(cmphash, 8, "MD5 for compare Hash (should be)");

    // Sending 2-nd packet with hash
    len=tcp_talk(ip, port, bufhash, 8, result, 0);
    if (len<=0) {
        printf("recv timeout\n");
        return -1;
    };
    if (len>=1023) {
        printf("Recv len: 0x%08X\n",len);
        printf("Too big pkt recv, exiting...\n");
        return -1;
    };

    // Display received pkt
    show_memory(result, len, "Send 2 pkt (8 byte hash) Result:");


    //i = 0;
    //if (memcmp (&byte(buffer,i), md5.hash, 8)) { /* breakpoint("16"); */ return -1; }     // must receive the hash now

    // must wait for the random bytes
    //n = recv (supernode->s, (char *)buffer, sizeof(buffer), 0);   

    // Sending packet with hash

    len2=tcp_talk_recv(ip, port, result2, 0);
    if (len2<=0) {
        printf("recv timeout\n");
        return -1;
    };
    if (len2>=1023) {
        printf("Recv len: 0x%08X\n",len);
        printf("Too big pkt recv, exiting...\n");
        return -1;
    };

    // Display received pkt
    show_memory(result2, len2, "added recv Result:");



    //showme_rc4(result, len);

    memcpy( (char *)buffer, result2, len2);
    
    //n = len+len2;
    //buffer = result;

    n = len2;

    if (n >= 16) {
        int length;

        i = 0;


        supernode_ivi = _bswap32(dword1(buffer,i));
        Skype_RC4_Expand_IV (supernode_ivi, &supernode_iv2[0], &rc4_recv, 1, 48);
        i += 4, n -= 4;

        RC4_crypt (&byte1(buffer,i), 10, &rc4_recv, 1);
        

        // Display received pkt
        //show_memory(&byte(buffer,i+2), 8, "cmp handshake:");

        show_memory(&byte(buffer,i), 10, "cmp handshake:");

        // did not decrypt, never seen anything other than this, 
        //although it could be \0\0\0\x\0\0\0\3 where x=0..3

        /*
        if (memcmp (&byte(buffer,i+2), "\0\0\0\1\0\0\0\x0F", 8)) { 
            printf ("breakpoint18");
            exit(-8);
        };
        if (memcmp (&byte(buffer,i+2), "\x00\x00\x00\x01\x00\x00\x00\x01", 8)) {
            printf ("breakpoint18");
            exit(-8);
        };
        */

        if (memcmp (&byte(buffer,i+2), "\x00\x00\x00\x01\x00\x00\x00", 7)) {
            printf ("breakpoint18");
            return -1;
        };

        // packet sequence number
        supernode_idi = bswap16(word1(buffer,i));
        i += 10, n -= 10;

        show_memory(&byte(buffer,i), n, "other handshake rc4 bef decode data:");

        RC4_crypt (&byte1(buffer,i), n, &rc4_recv, 0);

        // Display received pkt
        show_memory(&byte(buffer,i), n, "other handshake rc4 after decode data:");

        j = decode32 (&length, &byte1(buffer,i), n);
        j_global=j;
        printf("Decoded j (seq num): %d\n",j);

        // the packet is larger than what we have, should recv the rest
        if (j + length/2 > n) { 
            //breakpoint("19"); 
            return -1; 
        };

        // skipping the first random garbage packet
        i += j + length/2, n -= j + length/2;

        supernode_bytes = n;

        if (n) {
            // could be another packet, this one will have real data in it, already decrypted
            memcpy (supernode_data = malloc (n), buffer + i, n);
        } else {
            supernode_data = NULL;
        };


    } else {

        printf("size mismatch\n");

    };


    //memcpy( (char *)buffer2, (char *)buffer, len2);
    memset((char *)buffer2, 0x00, 48);

    supernode_ivo = rand32();
    
    // every direction [more like every packet] has its own IV
    dword(buffer2,0) = _bswap32(supernode_ivo);

    // sending a random amount of random garbage almost the way skype does it
    n = rand32 ()%45+4; 

    // packet sequence number
    supernode_ido = (u16)rand32();

    
    // byte swapped packet sequence number
    word(buffer2,4) = _bswap16((u16)supernode_ido);

    // has always been the same so far
    //memcpy (&byte(buffer2,6), "\0\0\0\1\0\0\0\3", 8);
    memcpy (&byte(buffer2,6), "\0\0\0\1\0\0\0\x0F", 8);

    // stupidly modified packet length
    byte(buffer2,14) = (u8)(n+1)*2+1;

    // have only seen 03 here so far, probably means "random garbage, ignore it"
    byte(buffer2,15) = 0x03;

    // Skype's random bytes are not really random here
    
    //for (i = 0; i+3 < n; i++) dword(buffer2,16+i) += rand32();

    //memcpy( (char*)buffer2+16, (char*)buffer+16, 11);

    Skype_RC4_Expand_IV (supernode_ivo, &supernode_iv2[0], &rc4_send, 1, 48);
    
    show_memory(&byte(buffer2,1), n+16, "3 pkt buffer bef:");
    
    RC4_crypt (&byte(buffer2,4), 10, &rc4_send, 1);
    RC4_crypt (&byte(buffer2,14), n+2, &rc4_send, 0);
    
    show_memory(&byte(buffer2,1), n+16, "3 pkt buffer aft rc4:");

    // connection lost
    //if (send (supernode->s, (char *)buffer, n+16, 0) != n+16) { breakpoint("20"); return -1; }

    memset(result, 0, 0x1000);

    // Sending 3 packet 
    len=tcp_talk_send((char *)buffer2,n+16);

    //if (len<=0) {
    //  printf("recv timeout\n");
    //  exit(1);
    //};

    if (len>=1023) {
        printf("Recv len: 0x%08X\n",len);
        printf("Too big pkt recv, exiting...\n");
        return -1;
    };

    // Display received pkt
    show_memory(result, len, "Now, 4 recv pkt Result:");

    // DH-384 setup complete going to login

    return j_global;
}

