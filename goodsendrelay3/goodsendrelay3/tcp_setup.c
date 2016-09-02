/*  
*
* Direct TCP connect to skype client
*
*/


#include "skype/skype_rc4.h"

// for aes
#include "crypto/rijndael.h"

// for 41 
#include "decode41.h"

//#include "defs.h"

// rc4 obfuscation
//extern void Skype_RC4_Expand_IV (RC4_context * const rc4, const u32 iv, const u32 flags);
//extern void RC4_crypt (u8 * buffer, u32 bytes, RC4_context * const rc4, const u32 test);

extern int Calculate_CRC32_For41(char *a2, int a3);
extern unsigned int Calculate_CRC32(char *crc32, int bytes);

// socket comm
extern int udp_talk(char *remoteip, unsigned short remoteport, char *buf, int len, char *result);
extern int tcp_talk(char *remoteip, unsigned short remoteport, char *buf, int len, char *result,int need_close);
extern int tcp_talk_recv(char *remoteip, unsigned short remoteport, char *result, int need_close);

// sha1 and rsa crypto function
extern int _get_sha1_data(char *buf, int len, char *outbuf, int need_convert);
extern int _get_decode_data(char *buf, int len, char *outbuf);
extern int _get_sign_data(char *buf, int len, char *outbuf);
extern int _get_unsign_cred(char *buf, int len, char *outbuf);
extern int _get_encode_data(char *buf, int len, char *outbuf);

// utils
extern int process_aes_crypt(char *data, int datalen, int usekey, int blkseq, int need_xor);
extern int show_memory(char *mem, int len, char *text);
extern int get_packet_size(char *data,int len);
extern int process_aes(char *buf, int buf_len, int usekey, int blkseq, int need_xor);
extern int first_bytes_correction(char *header, int header_len, char *buf, int buf_len);

// blobs encode
int encode41_setup1pkt(char *buf, int buf_limit_len);
int encode41_setup2pkt(char *buf, int buf_limit_len);


extern enum { AES_KEY_INIT, AES_KEY_OK };


    //
    // global data 
    //


    RC4_context rc4_send;
    RC4_context rc4_recv;

    u8 CHALLENGE_RESPONSE[0x80];
    u8 LOCAL_NONCE[0x80];

    int GLOBAL_STATE_MACHINE;

    u8 LOCAL_UIC[0x189];

    u8 REMOTE_AUTHORIZED188[0x189];
    uint REMOTE_AUTHORIZED188_LEN;

    u8 AFTER_CRED2[0x81];

    u8 remote_credentials[0x100];
    u8 remote_pubkey[0x80];

    u8 aes_key[0x20];

    u32 REMOTE_SESSION_ID;
    u32 LOCAL_SESSION_ID;

    // ex INIT_UNK
    u8 LOCALNODE_VCARD[0x1B];
    u8 REMOTENODE_VCARD[0x1B];

    u8 CLIENT_VERSION[0x100];

    // internal session chat
    uint BLOB_0_1;
    uint BLOB_0_2;
    uint BLOB_0_2__1;

    uint BLOB_0_9;
    uint BLOB_0_9__1;
    uint BLOB_0_A;
    uint BLOB_0_15;

    uint BLOB_0_9__2;
    uint BLOB_0_A__1;
    uint BLOB_0_15__1;

    uint BLOB_0_F;

    uint BLOB_0_A__2;
    uint BLOB_0_A__3;

    uint BLOB_1_9_ptr;
    uint BLOB_1_9_size;

    u32 confirm[0x100];
    u32 confirm_count;

    u8 MSG_TEXT[0x1000];

    u8 CHAT_STRING[0x100];

    u8 REMOTE_NAME[0x100];
    u8 LOCAL_NAME[0x100];

    u8 CHAT_PEERS[0x100];

    u8 CHAR_RND_ID[0x100];

    u8 CHAT_PEERS_REVERSED[0x100];

    uint HEADER_ID_REMOTE_FIRST;
    uint HEADER_ID_REMOTE_LAST;

    uint HEADER_ID_LOCAL_FIRST;
    uint HEADER_ID_LOCAL_LAST;

    uint HEADER_ID_SEND;
    uint HEADER_ID_SEND_CRC;

    uint GOT_CHAT_STRING_FROM_REMOTE;

    uint NEWSESSION_FLAG;
    uint NO_HEADERS_FLAG;

    u8 RECV_CHAT_COMMANDS[0x100];
    uint RECV_CHAT_COMMANDS_LEN;

    uint DEBUG_RC4;

    uint global_chatsync_stage;

    uint global_cmdid_pointer;

    uint global_chatsync_streamid;

    uint global_remote_chatsync_streamid;
    uint global_remote_cmd0D_streamid;

    uint global_unknown_cmd24_signed_id;
    uint global_unknown_cmd2A_signed_id;

    uint global_msg_time_sec;
    uint global_msg_time_min;

    uint pkt_7D_BLOB_00_01;
    uint pkt_7D_BLOB_00_19;

    uint pkt_7A_BLOB_00_13;

    uint pkt_cmd24_BLOB_00_1B;
    uint pkt_cmd24_BLOB_00_00;

    uint pkt_cmd2A_BLOB_00_00;

    uint pkt_cmd2B_BLOB_00_00;
    
    uint pkt_cmd13_BLOB_00_0F;

    uint HEADER_SLOT_CRC1;
    uint HEADER_SLOT_CRC2;
    uint HEADER_SLOT_CRC3;

    uint global_fail;

    // must initialize in proto seq(!)
    uint START_HEADER_ID;

    u8 NEWBLK[0x1000];
    uint NEWBLK_LEN;

    u8 CREDENTIALS[0x105];
    uint CREDENTIALS_LEN;

    // hash from CREDENTIALS with 00 00 00 01
    u8 CREDENTIALS_HASH[0x15];

    u8 CREDENTIALS2_HASH[0x15];

    //crc of credentials
    uint UIC_CRC;

    // global aes blkseq key
    int blkseq;

    //no ascii strings
    u8 AFTER_CRED[0x81];

    u8 CREDENTIALS188[0x189];
    uint CREDENTIALS188_LEN;

	char xoteg_pub[0x80+1];
    char xoteg_sec[0x80+1];

    char skype_pub[0x100+1];

    int newchatinit_flag;
    int restorechat_flag;

    int not_aes_counter;

	uint HEADER_ID_CMD27_CRC;
	uint HEADER_ID_CMD27_ID;

    int global_cmd10_needsync_flag;

    // relay specific

    u32 LOCAL_SESSION_ID_RELAY;

    int relay_connect_mode;

    // end of relay specific

    char global_destip[0x1000];
    unsigned short global_destport;

    // sql specific

    int insert_id[0x100];
    int insert_id_len;

    // end of sql specific

    //
    // end global data 
    //



unsigned int make_setup_global_init() {


    memset(&rc4_send, 0x00, sizeof(rc4_send));
    memset(&rc4_recv, 0x00, sizeof(rc4_recv));


    memset(CHALLENGE_RESPONSE, 0x00, 0x80);
    memset(LOCAL_NONCE, 0x00, 0x80);
    
    GLOBAL_STATE_MACHINE = 0;

    //xot_iam cert
    //+after..
    memcpy(LOCAL_UIC,
"\x00\x00\x01\x04\x00\x00\x00\x01\x77\x9E\x0F\xA9\x19\xE7\xFD\x5A"
"\x43\x87\x44\x0A\x7B\x9D\x27\xE3\x3D\xCE\xF5\xEA\x3C\xEB\x5C\x2C"
"\x3A\xD2\x80\x84\x73\x59\x60\x91\x1F\x1E\xBF\xE5\x94\x4D\x9B\xA0"
"\xED\xB9\xE9\xB6\xB8\xFC\xA5\x20\x4A\xBA\xC5\x55\x82\xA4\x32\x0C"
"\x1E\xD8\x50\xDE\xFD\x53\x8B\x38\xB8\x9B\x94\xD5\x95\xFF\x75\x7B"
"\x9D\x7C\x32\x85\xDA\x85\x15\x4D\x4D\x5F\x0A\x45\xCC\xDC\x3B\x2F"
"\xA9\x69\x6A\xD5\xE8\x35\xC0\xAC\x69\xB7\x28\x93\xA1\x58\x95\xD5"
"\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
"\x7C\x7B\x10\xD1\xD6\xFE\x38\x6E\x02\xA9\x94\xE0\xF0\xF6\x7B\x65"
"\xCF\x2F\x7F\x9B\x59\x5A\x3D\xCE\x11\x85\x0F\x46\xB3\x79\x52\x59"
"\x45\xF2\x68\x08\xF0\x67\x16\x7F\x8A\xE5\x08\x4A\x4A\xC0\xBD\xB2"
"\x7C\x0B\xF3\x90\x9D\xC1\x67\xB8\x68\xBA\x6C\x6B\x56\x69\xFD\xA6"
"\xAF\x93\x24\xAA\x5C\x83\x22\x87\x22\x8E\xD6\xFA\x24\xBA\x89\xAA"
"\xBA\x1E\x92\xE8\xDA\x00\x01\x9D\xC6\xEC\x4D\x51\x0E\xC2\xAD\x09"
"\xAB\x73\x1F\xFF\xFE\x4B\x74\xA4\x87\x19\xF7\x03\xA5\x2C\xBA\x64"
"\x8D\x28\x12\x7D\x41\xBF\x82\xEE\x3C\xF1\x6C\x20\x18\xBC\xA4\x23"
"\x5E\x99\x69\x0C\x13\x7D\x69\xB8\x33\x94\xCC\x02\x4B\xA0\x83\xA3"
"\x00\xBC\x7A\x7C\x11\x85\xBA\x7A\xF1\x2E\x8A\xA6\x20\x62\x6D\x08"
"\x8B\xDD\x75\x92\x50\x15\xB5\xD1\x13\xCE\x2A\xB3\xB8\x1B\x7B\xE2"
"\xD0\x8F\x1E\xF7\xEB\x23\xEC\x76\x51\xBB\x97\x04\x9F\xA3\x45\x49"
"\x54\x69\xF8\x6C\x0E\x21\x13\x75\xD2\x49\x40\x4E\x08\x30\x0E\xCF"
"\xF4\xF1\x0A\x56\xD0\x8F\x31\x0A\x43\xFD\xA0\x83\xD8\x4D\x04\x0F"
"\x4B\xBC\x92\xC5\xBA\x26\xBF\xDB\xFB\xA3\xB1\x67\x63\x05\x1C\xF1"
"\x63\x6A\xA6\x7E\x40\x0F\x28\xD1\xAB\xBE\x49\xC3\x52\xAC\x23\x9D"
"\x9F\x80\xA3\x50\x58\xD5\xC1\xFE"
	,0x189);




    memcpy(REMOTE_AUTHORIZED188,
"\x00\x00\x01\x04\x00\x00\x00\x01\x94\x8E\xD8\xA1\x58\x6D\x7A\x36"
"\x15\xC8\xFA\x6C\xEA\x81\x44\x92\x3D\xD8\xC6\x82\xB2\x35\x7C\x8E"
"\x7A\x73\x3F\xC5\x90\xB6\xAD\xEF\xAE\x9B\x89\x20\xD5\xFF\x6F\x68"
"\xB3\xAC\xDA\x10\x0B\xB0\x2B\x45\xEA\x60\x77\x8D\x98\x3E\x25\x64"
"\xF6\x01\x79\xA8\xDA\x97\x9D\xB6\x54\x49\x15\xA7\xA1\x32\x40\x96"
"\x5A\xC4\x8D\x6E\x9A\x0C\x40\x84\xAB\xE2\x1F\x61\xE5\x9A\x65\x5B"
"\x32\x85\x9A\x03\x5C\xBF\x33\x16\xD2\xEB\x14\xB6\xB3\x8D\xDC\x1A"
"\x73\xA0\xAC\x0C\xB8\x4C\xE0\x8C\x49\xEE\x55\x88\xD1\xDA\x38\x69"
"\x05\x3D\xBA\x12\x77\x6F\x26\xBA\x6F\x16\x70\x95\xFD\x02\x19\xE3"
"\x99\xA5\x7C\x91\x5F\xD4\xE6\x45\x55\x88\x79\x8A\x30\x40\xD9\x9A"
"\x15\xE8\x00\xC8\xEA\x49\x54\xC0\xC0\xB5\x34\xE0\x78\x10\x45\x91"
"\x90\x10\xD2\x1A\x04\x91\xF7\x45\x55\xA3\x9D\xD8\x6C\xA7\xA0\x59"
"\xEF\x3F\x5C\x8C\x36\x19\xC0\x90\xC7\x3A\x53\x78\x89\xA0\x4F\xAB"
"\x9B\x73\xCC\x01\xB4\x29\xBC\x4C\x9E\xCF\x47\x0D\xFB\xA8\xB8\x47"
"\x9B\x3F\x74\xAC\xA6\x7D\xFF\xE3\xD9\x4E\xFB\x0D\xB1\x1C\xAF\x5A"
"\xB8\xDC\xF1\x0B\xEB\x0A\x40\x70\x87\x51\x78\xE1\x7D\xF6\x79\x8B"
"\x20\x52\x8B\xCF\xDA\x60\x36\x58\x5E\x1D\x40\x4A\x21\x65\x25\xF5"
"\x1C\x5A\xBE\xD2\xAA\x37\x8A\xD6\x48\x1C\x0C\x96\x3D\x92\x33\xF1"
"\xA8\x6D\x31\x35\x28\xB0\xE4\x80\xD7\x79\x2A\x4C\xB3\x97\x63\x53"
"\x72\x6B\x61\x4C\xF1\x96\xD8\x9A\x24\xF5\x54\x4A\xC5\xA0\x2C\x4C"
"\x7A\xE4\x78\xE2\xB9\xB2\x22\x5B\xFF\x08\x8E\xB5\x16\x59\xB0\x17"
"\xC1\xE6\x0B\x44\x92\xF8\xF6\xDA\x83\x6B\xC0\x03\xE4\x1D\x76\xFF"
"\x6A\xBC\x3D\x30\xB0\x1D\x47\x09\xD8\x20\x55\x79\xAD\x40\x7C\x37"
"\x0C\x5F\x30\xAE\x54\x05\xE9\x3D\xE4\x2D\x5E\xE1\x89\xA9\x61\xDA"
"\xA0\xFD\x89\xF1\x1B\x36\xFF\x9A"
    ,0x189);

    REMOTE_AUTHORIZED188_LEN=0x188;


    memcpy(AFTER_CRED2,
"\x4B\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB"
"\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB"
"\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB"
"\xBB\xBB\xBB\xBB\xBA\xBA\xBA\xBA\xBA\xBA\xBA\xBA\xBA\x1D\xC6\x85"
"\xD1\xBC\xA2\xCA\x49\x5F\x22\xCC\xD9\x75\xDB\x35\x5C\x58\x9A\x98"
"\xB2\x62\x75\x64\x64\x79\x5F\x61\x75\x74\x68\x6F\x72\x69\x7A\x65"
"\x64\x78\x6F\x74\x65\x67\x5F\x69\x00\x00\x00\x3E\xF9\xC4\xEA\xE9"
"\x8B\xA2\x08\x9E\x8D\xD7\xE2\x71\xD1\x3E\x53\xD2\xC6\xEE\x96\xBC"
    ,0x81);


    memset(remote_credentials, 0x00, 0x100);
    memset(remote_pubkey, 0x00, 0x80);

    memset(aes_key,0x00, 0x20);

    REMOTE_SESSION_ID = 0x00;
    LOCAL_SESSION_ID = 0x00;

    LOCAL_SESSION_ID = 0x6FB6;


    // init later
    //LOCALNODE_VCARD
    //REMOTENODE_VCARD

    memset(LOCALNODE_VCARD, 0x00, 0x1B);
    memset(REMOTENODE_VCARD, 0x00, 0x1B);

    //skype v5.5
    //u8 CLIENT_VERSION[0x100]="0/5.5.0.124//"
    strcpy(CLIENT_VERSION,"0/6.16.0.10//");

    // internal session chat
    BLOB_0_1 = 0;
    BLOB_0_2 = 0;
    BLOB_0_2__1 = 0;

    BLOB_0_9 = 0;
    BLOB_0_9__1 = 0;
    BLOB_0_A = 0;
    BLOB_0_15 = 0;

    BLOB_0_9__2 = 0;
    BLOB_0_A__1 = 0;
    BLOB_0_15__1 = 0;

    BLOB_0_F = 0;

    BLOB_0_A__2 = 0;
    BLOB_0_A__3 = 0;

    BLOB_1_9_ptr=0x4540A9FC;
    BLOB_1_9_size=0x73B99134;


    memset(confirm, 0x00, 0x100);
    confirm_count = 0;

    memset(MSG_TEXT, 0x00, 0x1000);

    memset(CHAT_STRING, 0x00, 0x100);

    memset(REMOTE_NAME, 0x00, 0x100);
    memset(LOCAL_NAME, 0x00, 0x100);

    memset(CHAT_PEERS, 0x00, 0x100);

    strcpy(CHAR_RND_ID,"bc5ffd9299000000");

    memset(CHAT_PEERS_REVERSED, 0x00, 0x100);


    HEADER_ID_REMOTE_FIRST = 0;
    HEADER_ID_REMOTE_LAST = 0;

    HEADER_ID_LOCAL_FIRST = 0;
    HEADER_ID_LOCAL_LAST = 0;

    HEADER_ID_SEND = 0;
    HEADER_ID_SEND_CRC = 0;

    GOT_CHAT_STRING_FROM_REMOTE = 0;

    NEWSESSION_FLAG = 0;
    NO_HEADERS_FLAG = 0;

    memset(RECV_CHAT_COMMANDS,0x00,0x100);
    RECV_CHAT_COMMANDS_LEN = 0;

    DEBUG_RC4 = 0;

    global_chatsync_stage = 0;
    global_cmdid_pointer = 0;

    global_chatsync_streamid = 0x00;

    global_remote_chatsync_streamid = 0x00;
    global_remote_cmd0D_streamid = 0x00;


    global_unknown_cmd24_signed_id = 0x00;
    global_unknown_cmd2A_signed_id = 0x00;

    global_msg_time_sec = 0x00;
    global_msg_time_min = 0x00;


    pkt_7D_BLOB_00_01 = 0;
    pkt_7D_BLOB_00_19 = 0;

    pkt_7A_BLOB_00_13 = 0;

    pkt_cmd24_BLOB_00_1B = 0;
    pkt_cmd24_BLOB_00_00 = 0;

    pkt_cmd2A_BLOB_00_00 = 0;

    pkt_cmd2B_BLOB_00_00 = 0;

    pkt_cmd13_BLOB_00_0F = 0;

    HEADER_SLOT_CRC1 = 0;
    HEADER_SLOT_CRC2 = 0;
    HEADER_SLOT_CRC3 = 0;


    global_fail = 0;

    // must initialize in proto seq(!)
    START_HEADER_ID = 0x00;

    memset(NEWBLK,0x00, 0x1000);
    NEWBLK_LEN = 0;



    memcpy(CREDENTIALS,
"\x00\x00\x00\x01\x50\x6A\xF3\xC8\x9B\x67\xD0\x54\x4F\x36\xA0\x91"
"\x4A\xE8\x33\xF1\x72\xB6\xDF\x6A\xCB\x31\xAF\xCB\x07\x7E\x02\xA4"
"\x4A\xA8\xD1\x08\x32\x56\xEC\x76\x7F\x28\xC2\x4D\x71\x59\xB8\xB3"
"\x6E\xCF\xED\x9D\x38\x38\xF5\xFA\x89\xE3\xC4\x6D\xB5\xFE\x80\x97"
"\x7F\x67\x4E\xFE\xF6\xB9\x4D\xE2\x54\xD7\x90\xE1\x5E\xE9\xFF\x70"
"\xCF\xC2\x57\x2D\xF2\x74\xC2\xE3\x3C\x9A\x38\x14\xE2\xBB\xED\x51"
"\x26\xB5\xCA\x8F\xCA\x5E\x8D\x51\xCB\x01\x26\x01\x9E\xE2\xE1\x0C"
"\x7B\x79\x27\xC8\x62\xD2\x41\x6D\x39\xCE\x01\x68\x70\x56\x1D\xB7"
"\x72\x0C\x4F\x40\x82\x34\x38\x1F\x85\x72\x96\xA1\xA7\x50\x16\x64"
"\xD9\x23\x1F\x51\x35\xAE\x92\x5F\xF2\xF6\x87\x88\xA5\xD1\x1A\xF8"
"\xC0\x0A\xBF\x29\x56\xF9\x3D\x7C\xA2\x59\x7B\xD6\x4A\xA8\x55\x5B"
"\x6A\x7F\xB9\x14\xB8\x0E\xA8\x47\x3F\xB3\x92\x3B\x3E\x8B\x4C\x7B"
"\x74\xD6\xB6\xC0\x6E\xFF\xD6\xA4\x38\xAE\x0D\x7C\x75\xC6\x71\x65"
"\x62\x7A\xF7\x92\x98\x57\xB0\xBF\x52\x33\x59\xF8\x9F\xAF\x31\x80"
"\x78\x20\xF1\xDE\xDE\x07\xAD\x89\xBF\x7E\xBD\x9E\x74\xA3\x71\x07"
"\x70\x26\xE6\x77\x5D\xC8\x38\xCD\x9E\x6A\x10\x57\x02\xAF\xA0\x45"
"\xEC\xC9\xBB\xBD"
    ,0x105);


    CREDENTIALS_LEN=0x104;

    // hash from CREDENTIALS with 00 00 00 01
    memset(CREDENTIALS_HASH, 0x00, 0x15);

    memset(CREDENTIALS2_HASH, 0x00, 0x15);


    //crc of credentials
    //uint UIC_CRC=0xEFE9B321;
    UIC_CRC = 0;

    // global aes blkseq key
    blkseq = 0;


    //no ascii strings
    memcpy(AFTER_CRED,
"\x4B\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBA\xDD\xDD"
"\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
"\xDD\xDD\x42\xC4\x69\x43\x9E\x69\xB5\xC8\xE1\x06\xEE\x01\x4B\x50"
"\x63\x6B\x98\x25\x45\x5E\x38\x3C\xE9\xFF\x54\x2C\x47\x8D\xB1\x7C"
"\xF1\x33\x1F\x10\x77\x24\x9A\x9B\x4A\x9C\xB3\x3D\xFF\x4B\xB3\xD7"
"\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC"
"\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xAA\xAA\xAA\xAA\xAA"
"\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xBC"
    ,0x81);

    memcpy(CREDENTIALS188,
"\x00\x00\x01\x04\x00\x00\x00\x01\xA7\xCF\xDF\xF5\xA9\x69\x80\x2C"
"\x56\x12\xD5\x8B\x4B\xB1\x6A\x51\x0B\xF4\xE1\x69\x47\x96\x89\x2D"
"\x82\xA2\x16\xB7\x19\xC9\x52\xDF\x08\x84\x0D\x28\x04\x0F\x10\x6F"
"\x07\xD4\xFF\x3E\x64\x80\x34\x36\xDC\x25\x5F\x79\xF1\x7F\x1C\x4C"
"\x90\x9C\x03\xE2\xEF\x9D\xB9\xC6\xD9\x52\x55\xD4\xC0\xFE\x31\x6E"
"\x08\xEA\xFA\xC9\x61\xBB\xF8\xDA\xF7\x2E\x8A\x13\x16\xB2\x12\x7E"
"\x17\x38\xD7\x13\x2E\x85\x1D\x27\x63\x71\xDD\x48\xA9\x95\x37\xF6"
"\xFE\x62\x76\x31\xF8\x0E\x5E\x4B\x1A\x8C\xC2\xF4\x14\x80\x5E\x96"
"\x1C\xCB\x81\xE7\xDC\x5A\xF5\xE7\xD8\x6D\xE7\x9F\xF2\xAD\x77\xA1"
"\xE1\xA4\x03\xCF\x57\x41\xC6\x61\x82\xD8\xBF\x24\x7A\x1F\xC4\x23"
"\x08\xDC\xC2\x5A\x63\x79\x95\xFF\x0B\x3E\x1E\xF8\x7A\x6C\x49\x05"
"\x00\x45\x5E\xDD\xAB\x9F\x19\xF6\x50\xD1\x4A\xB9\x02\x92\xC5\x62"
"\x6E\x27\x44\xDC\x68\x06\x09\xFD\x1D\x6E\xC1\xC0\x0F\x3D\x90\xE4"
"\x1A\xF9\xDE\x46\x5B\x27\xB6\x9F\x48\xAC\xB4\x1A\x95\x92\x8C\x7D"
"\xE2\x9D\xA3\xA7\xC7\x06\x95\x2A\xFC\xD3\x86\xC3\x46\x4E\x7E\x9F"
"\xF8\xA6\x2C\xE9\x5D\x94\xFC\x95\xCC\xC0\x83\x84\xC0\x40\x35\xDD"
"\xA0\x72\x6B\x78\x7C\x26\x3E\x68\xD1\x95\xD9\xB8\xBD\xC7\x22\x63"
"\x43\xDD\x7F\x70\xB3\x23\x61\x7D\x13\x59\x3B\xD2\x12\x8D\x8A\x9F"
"\xA5\xB0\x6F\x73\xB7\x2A\x71\xA6\x93\x47\xE1\x07\x59\xE6\x25\x68"
"\xE5\xC5\x42\x0C\x4D\x68\x6B\x8B\xD8\xD6\x28\xD0\x1D\x1C\xF7\xF9"
"\x63\x66\x9C\xA6\x57\xB5\x1F\x8B\x4B\x40\xD8\xA7\xAB\x93\x73\x96"
"\x00\x0C\xE8\x6F\x4A\xAB\x3A\xEA\xE7\x94\x3B\x75\x18\x6B\x21\x88"
"\xD9\xA7\x90\xBB\x9A\x10\x25\xED\xF7\xA2\x88\xAE\x48\x4C\x24\xA0"
"\xF6\x39\xD3\x0E\x67\xA9\x78\x74\xFA\xA6\x34\xF3\x7C\x97\x52\x53"
"\x7F\x49\xF1\x9D\xF5\xBA\xE8\x5D"
    ,0x189);


    CREDENTIALS188_LEN = 0x188;

    memcpy(xoteg_pub, 
"\xC5\x69\xE5\x5F\x12\x2B\x46\x86\x70\x1C\x10"
"\xF8\x0A\x17\x1F\x95\x57\x55\xBC\xD2\xC1\x03\x5B\x3F\xD0\x84\x86"
"\xE2\xF1\x10\x96\x87\x16\xD3\x0C\x2B\x33\x76\x9E\x12\x77\x97\x7F"
"\xE7\xF7\xFF\xD9\xB9\xBB\xF5\x19\xE3\x2A\xFA\x56\xE1\x3B\x4A\x45"
"\xEF\x29\xE0\x95\x23\xFE\x58\x42\x72\x27\xAD\x03\xAF\x6E\x3C\xF7"
"\x05\xE4\x9F\x4D\xF4\xA5\x91\xFE\x8F\xDE\xDE\x1B\xA0\xD9\x94\xD7"
"\x43\x4F\x90\xEF\x38\xE1\xB8\x1B\xD2\xDC\x3D\xCA\x6F\x8B\x50\x60"
"\x94\xA4\x6B\x14\x10\x5B\x5F\xB1\xCA\x73\x1D\x56\x93\x5D\xF2\xF5"
"\x5E\x71\xC0\xF9\x95"
    ,0x81);

    memcpy(xoteg_sec,
"\xC3\xD3\x81\xF6\x46\xDD\xAA\xBD\xDD\x23\xDA\x29\x52\x49\x11\xC9"
"\x60\xB2\xE9\xF5\xDE\x04\xE8\x55\x6B\x10\xAB\x85\x1F\x40\x27\x31"
"\xA6\x10\x80\x77\xB2\x3B\x2E\x1E\x7F\x87\x47\x17\xE2\x48\x67\xBF"
"\xF8\x94\xEF\xB3\x0A\x84\xFD\xFD\xBA\x84\xB8\xCE\xBF\xA9\xCA\x06"
"\x06\x22\x38\x00\xAD\xF4\xB0\x9D\x80\x88\x86\xEA\x85\x51\x45\x18"
"\xDD\xD7\x32\xD3\x85\x13\x20\x8E\x49\xA2\x92\xE8\xFF\x70\x5B\xBD"
"\x99\xE3\x9D\x21\xB0\xD0\xF4\xC2\xF6\xFD\xC9\xA5\x3F\xDE\xF7\x9E"
"\x27\x84\x3D\xB9\x58\xB5\xD6\xEB\xBC\xE0\xCD\x17\xE3\x47\x19\x99"
    ,0x81);

    memcpy(skype_pub,
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
    ,0x101);

    newchatinit_flag = 0;
    restorechat_flag = 0;

    not_aes_counter = 0;

	HEADER_ID_CMD27_CRC = 0;
	HEADER_ID_CMD27_ID = 0;

    global_cmd10_needsync_flag = 0;

    // relay specific

    LOCAL_SESSION_ID_RELAY = 0x6FB6;

    memset(global_destip, 0x00, 0x1000);
    global_destport = 0;

    relay_connect_mode = 0;

    // end of relay specific

    // sql specific

    memset(insert_id, 0x00, sizeof(insert_id));
    insert_id_len = 0;

    // end of sql specific


    // hardcoded in tcp_pkt.c
    // my conn id to relay
    LOCAL_SESSION_ID=0x6FB6;

    memcpy(LOCALNODE_VCARD,"\xE0\x3E\x31\xAE\x40\x3A\xE0\x12\x00\x75\x03\x25\xC7\xE1\x08\x41\x37\xDF\x19\x9C\x55\xC0\xA8\x01\x4B\xE1\x08",0x1B);
    memcpy(REMOTENODE_VCARD,"\x70\xE7\xDC\x1C\xE2\x82\x8C\x31\x00\xA8\x3F\x7D\x7D\x9C\x5F\x00\x00\x00\x00\x00\x00\xAC\x1F\xFF\xF9\x9C\x5F",0x1B);


    return 0;
};

////////////////////////////
////////////////////////////
////////////////////////////


unsigned int make_setup_prepare() {

    GOT_CHAT_STRING_FROM_REMOTE = 0;

//    LOCAL_SESSION_ID = 0x1B65;

    memcpy(LOCALNODE_VCARD,"\xE0\x3E\x31\xAE\x40\x3A\xE0\x12\x00\x75\x03\x25\xC7\xE1\x08\x41\x37\xDF\x19\x9C\x55\xC0\xA8\x01\x4B\xE1\x08",0x1B);
    memcpy(REMOTENODE_VCARD,"\x70\xE7\xDC\x1C\xE2\x82\x8C\x31\x00\xA8\x3F\x7D\x7D\x9C\x5F\x00\x00\x00\x00\x00\x00\xAC\x1F\xFF\xF9\x9C\x5F",0x1B);

    make_credentials188_block();

	UIC_CRC=Calculate_CRC32( (char *)CREDENTIALS,CREDENTIALS_LEN);
	debuglog("UIC_CRC = %08X\n",UIC_CRC);


    return 0;
};


unsigned int make_credentials188_block() {

	memcpy(CREDENTIALS188+0x04,CREDENTIALS,CREDENTIALS_LEN);

	/////////////////////
	// SHA1 hash
	/////////////////////
	//make hash of CREDENTIALS 0x104 bytes.
	//save to CREDENTIALS_HASH
	if (1) {
		char *buf;
		char *outbuf;

		buf=malloc(0x1000);
		outbuf=malloc(0x1000);

		memset(buf,0,0x200);
		memset(outbuf,0,0x200);

		//prepare data for hashing
		memcpy(buf,CREDENTIALS,CREDENTIALS_LEN);

		//print it
		show_memory(buf, CREDENTIALS_LEN, "SHA1 input");

		//make sha1 hash
		_get_sha1_data(buf, CREDENTIALS_LEN, outbuf, 1);

		//print it
		show_memory(outbuf, 0x14, "SHA1 output(hash)");

		//copy hash
		memcpy(CREDENTIALS_HASH,outbuf,0x14);

	};



	// modify hash
	memcpy(AFTER_CRED+0x0E,CREDENTIALS_HASH, 0x14);
	//modify init_unk
	memcpy(AFTER_CRED+0x60,LOCALNODE_VCARD, 0x1B);

	
	/////////////////////
	// SHA1 hash
	/////////////////////
	//make hash of AFTER_CRED 0x80 bytes.
	//save to CREDENTIALS_HASH
	if (1) {
		char *buf;
		char *outbuf;

		buf=malloc(0x1000);
		outbuf=malloc(0x1000);

		memset(buf,0,0x200);
		memset(outbuf,0,0x200);

		//prepare data for hashing
		memcpy(buf,AFTER_CRED+0x0E,0x80-0x14-1-0x0E);

		//print it
		show_memory(buf, 0x80-0x14-1-0x0E, "SHA1 input");

		//make sha1 hash
		_get_sha1_data(buf, 0x80-0x14-1-0x0E, outbuf, 1);

		//print it
		show_memory(outbuf, 0x14, "SHA1 output(hash)");

		//copy hash
		memcpy(AFTER_CRED+0x80-0x14-1,outbuf,0x14);

	};




	///////////////////////
	//RSA sign
	///////////////////////
	//for sign 0x80 byte after credentials
	if (1) {
		char *buf;
		char *outbuf;


		buf=malloc(0x1000);
		outbuf=malloc(0x1000);

		memset(buf,0,0x200);
		memset(outbuf,0,0x200);


		//copy
		memcpy(buf,AFTER_CRED,0x80);
		
		//before RSA sign-ing
		show_memory(buf, 0x80, "RSA SIGN input");

		//make rsa sign
		_get_sign_data(buf, 0x80, outbuf);

		//copy rsa sign to credentials188 buffer
		memcpy(CREDENTIALS188+0x100+0x08,outbuf,0x80);

		//print credentials 0x188
		show_memory(CREDENTIALS188, CREDENTIALS188_LEN, "RSA SIGN cred188");

	};
	
	return 0;
};


//////////////////////
// tcp first packet //
//////////////////////
unsigned int make_tcp_client_sess1_pkt1(char *ip, unsigned short port) {
	u8 result[0x1000];
	u8 recvbuf[0x1000];
	int len;
	int tmplen;
	int recvlen;
	char *pkt;
	int ret;

	u8 buf1[0x1000];
	int buf1_len;
	u8 buf1header[0x10];
	int buf1header_len;


	debuglog("Sending first TCP packet\n");

	GLOBAL_STATE_MACHINE = AES_KEY_INIT;
	
	///////////////////////////////
	// first 41 
	///////////////////////////////

	memset(buf1,0,sizeof(buf1));
  	buf1_len=encode41_setup1pkt(buf1, sizeof(buf1));
	show_memory(buf1, buf1_len, "setup1pkt");

	main_unpack(buf1, buf1_len);

    do_proto_log(buf1, buf1_len, "setup1pkt");

	// aes encrypt block 1
	blkseq=0x00;
	buf1_len=process_aes(buf1, buf1_len, 0, blkseq, 0);


	/////////////////////////////////////
	// first bytes correction
	/////////////////////////////////////
	// calculate for 4 and 5 byte fixing
    //memset(buf1header, 0x00, 0x10);

	buf1header_len=first_bytes_correction(buf1header, sizeof(buf1header)-1, buf1, buf1_len);
	show_memory(buf1header, buf1header_len, "setup1header");


	/////////////////////////////////
	// assembling pkt for sending
	/////////////////////////////////
	pkt=(char *)malloc(0x1000);
	memset(pkt,0,0x1000);
	len=0;

	// header
	memcpy(pkt+len,buf1header,buf1header_len);
	len=len+buf1header_len;
	// aes
	memcpy(pkt+len,buf1,buf1_len);
	len=len+buf1_len;


	// Encrypt data

	// Initialize RC4 obfuscation
	//iv = rnd;
	//debuglog("Local RC4 IV=0x%08X\n",iv);

	// Expand IV(our rnd)
	//Skype_RC4_Expand_IV_OLD (&rc4_send, iv, 1);
	
	//Skype_RC4_Expand_IV_new();

	// Encrypt RC4
	show_memory(pkt, len, "Before RC4 encrypt");
	RC4_crypt (pkt, len, &rc4_send, 0);
	show_memory(pkt, len, "After RC4 encrypt");

	// display pkt
	show_memory(pkt, len, "Send pkt");

	// send pkt
	len=tcp_talk(ip,port,pkt,len,result,0);
	if (len<=0) {
		debuglog("recv timeout\n");
		return len;
	};
	
	// recv pkt
	show_memory(result, len, "Result");
	
	// copy pkt
	recvlen=len;
	memcpy(recvbuf,result,recvlen);



	show_memory(recvbuf, recvlen, "Before RC4 decrypt");
	RC4_crypt (recvbuf, recvlen, &rc4_recv, 0);
	show_memory(recvbuf, recvlen, "After RC4 decrypt");

	ret = process_recv_data(recvbuf, recvlen);
    if (ret < 0) { return -1; };

	return 1;
};


///////////////////////////////
//tcp second packet
///////////////////////////////
unsigned int make_tcp_client_sess1_pkt2(char *ip, unsigned short port){
	char result[0x1000];
	u8 recvbuf[0x1000];
    int ret;
	int len;
	int tmplen;
	int recvlen;
	int blkseq;
	char *pkt;

	u8 buf1[0x1000];
	int buf1_len;
	u8 buf1header[0x10];
	int buf1header_len;

	int checked_pkt_len;
	int i;

	char header41[0x100];
    int debug45_41;

    debug45_41 = 0;

	if (debug45_41) debuglog("Sending second TCP setup packet\n");


	/////////////////////////////
	// SHA1 digest
	/////////////////////////////
	// for getting aes key nonce1 (local)
	if (1) {
		char *buf;
		char *outbuf;

		//make local nonce
		char tmp[]=
"\xF5\x4A\x48\xA6\x37\x73\xE3\x42\xB6\x75\x1A\x61\x4D\x08\xDB\xB6"
"\xF5\x4A\x48\xA6\x37\x73\xE3\x42\xB6\x75\x1A\x61\x4D\x08\xDB\xB6"
"\xF5\x4A\x48\xA6\x37\x73\xE3\x42\xB6\x75\x1A\x61\x4D\x08\xDB\xB6"
"\xF5\x4A\x48\xA6\x37\x73\xE3\x42\xB6\x75\x1A\x61\x4D\x08\xDB\xB6"
"\xF5\x4A\x48\xA6\x37\x73\xE3\x42\xB6\x75\x1A\x61\x4D\x08\xDB\xB6"
"\xF5\x4A\x48\xA6\x37\x73\xE3\x42\xB6\x75\x1A\x61\x4D\x08\xDB\xB6"
"\xF5\x4A\x48\xA6\x37\x73\xE3\x42\xB6\x75\x1A\x61\x4D\x08\xDB\xB6"
"\xF5\x4A\x48\xA6\x37\x73\xE3\x42\xB6\x75\x1A\x61\x4D\x08\xDB\xB6"
;
		memcpy(LOCAL_NONCE, tmp, 0x80);
		// some strange thing, but needed
		LOCAL_NONCE[0]=0x01;

		
		buf=malloc(0x1000);
		outbuf=malloc(0x1000);

		memset(buf,0,0x200);
		memset(outbuf,0,0x200);

		// first integer is 0x00000000 !!!
		memcpy(buf+4,LOCAL_NONCE,0x80);
		
		// show data for hashing
		// integer(0x00) and 0x80 nonce
		if (debug45_41) show_memory(buf, 0x84, "local NONCE input");

		// making sha1 hash on nonce
		//get_sha1_data(buf, 0x84, outbuf, 1);
		
		_get_sha1_data(buf, 0x84, outbuf, 0);


		// copy local part of aes key
		memcpy(aes_key,outbuf,0x10);

		// show full aes session key
		if (debug45_41) show_memory(aes_key, 0x10, "AES KEY local");
	};

	/////////////////////////////
	// RSA encode
	/////////////////////////////
	// for encrypting local nonce
	if (1) {
		char *buf;
		char *outbuf;


		buf=malloc(0x1000);
		outbuf=malloc(0x1000);

		memset(buf,0,0x200);
		memset(outbuf,0,0x200);

		// copy encrypted nonce
		memcpy(buf,LOCAL_NONCE,0x80);
		
		// rsa decrypt nonce
		if (debug45_41) show_memory(buf, 0x80, "Before RSA encrypt nonce");
		_get_encode_data(buf, 0x80, outbuf);
		if (debug45_41) show_memory(outbuf, 0x80, "After RSA encrypt nonce");

		// copy decrypted nonce
		memcpy(LOCAL_NONCE,outbuf,0x80);

	};





	//////////////////////////////////////////////////
	// modify nonce blob, in aes data
	//////////////////////////////////////////////////
	//memcpy(aes_41data+0x22d,local_nonce,0x80);


	//////////////////////////////////////////////////
	// modify challenge response blob, in aes data
	//////////////////////////////////////////////////
	//emcpy(aes_41data+0x1a6,CHALLENGE_RESPONSE,0x80);

	//////////////////////////////////////////////////
	// change uic cert to new, becouse of expire 
	//////////////////////////////////////////////////
	//memcpy(aes_41data+0x17,aes_41data_remote_uic,0x188);

	//////////////////////////////////////////////////
	// change uic cert2, becouse of keys change
	//////////////////////////////////////////////////
	//memcpy(aes_41data+0x02B1,aes_41data_local_uic,0x188);
	
	
	
	///////////////////////////////
	// first 41 
	///////////////////////////////

	memset(buf1,0,sizeof(buf1));
  	buf1_len=encode41_setup2pkt(buf1, sizeof(buf1));
	if (debug45_41) show_memory(buf1, buf1_len, "setup2pkt");

    
	if (debug45_41) main_unpack(buf1, buf1_len);

    do_proto_log(buf1, buf1_len, "setup2pkt");

	// aes encrypt block 1
	blkseq=0x01;
	buf1_len=process_aes_nolog(buf1, buf1_len, 0, blkseq, 0);


	/////////////////////////////////////
	// first bytes correction
	/////////////////////////////////////
	// calculate for 4 and 5 byte fixing
	buf1header_len=first_bytes_correction(buf1header, sizeof(buf1header)-1, buf1, buf1_len);
	if (debug45_41) show_memory(buf1header, buf1header_len, "setup1header");


	/////////////////////////////////
	// assembling pkt for sending
	/////////////////////////////////
	pkt=(char *)malloc(0x1000);
	memset(pkt,0,0x1000);
	len=0;

	//header
	memcpy(pkt+len,buf1header,buf1header_len);
	len=len+buf1header_len;
	
	//aes
	memcpy(pkt+len,buf1,buf1_len);
	len=len+buf1_len;
	

	/////////////////////////////////
	// RC4 encrypt pkt
	/////////////////////////////////
	if (debug45_41) show_memory(pkt, len, "Before RC4 encrypt");		
	RC4_crypt (pkt, len, &rc4_send, 0);
	if (debug45_41) show_memory(pkt, len, "After RC4 encrypt");		


	// display pkt
    // ok for print in debug
	if (debug45_41) show_memory(pkt, len, "Send pkt");

	// send pkt
	len=tcp_talk(ip,port,pkt,len,result,0);
	if (len<=0) {
		if (debug45_41) debuglog("recv timeout\n");
		if (debug45_41) debuglog("Remote host dropped connection. Check if Credentials expired.\n");
		return len;
	};
	
	// recv pkt
    // ok for print in debug
	if (debug45_41) show_memory(result, len, "Result");

	// copy pkt
	recvlen=len;
	memcpy(recvbuf,result,recvlen);


	/////////////////////////////////
	// RC4 decrypt pkt
	/////////////////////////////////
	if (debug45_41) show_memory(recvbuf, recvlen, "Before RC4 decrypt");
	RC4_crypt (recvbuf, recvlen, &rc4_recv, 0);
	if (debug45_41) show_memory(recvbuf, recvlen, "After RC4 decrypt");

	ret = process_recv_data(recvbuf, recvlen);
    if (ret < 0) { return -1; };

    //
    // wait until get 57 41 pkt and do AES_KEY_OK
    // should work for both, relay and direct connections
    //
    while (GLOBAL_STATE_MACHINE == AES_KEY_INIT) {
		ret = make_tcp_client_sess1_recv_loop();
        if (ret < 0) { return ret; };
    };

	return ret;
};
