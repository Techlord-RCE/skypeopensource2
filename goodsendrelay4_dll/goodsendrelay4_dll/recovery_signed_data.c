/*
 *   Decoding 04-04 signed blocks by Efim Bushmanov
 *
 */


#include <stdio.h>
#include <stdlib.h>

#include <string.h>
#include <time.h>


#include "miracl_lib/miracl.h"

#include "short_types.h"

extern int show_memory(char *mem, int len, char *text);

extern int get_04_03_blob(u8 *buf, int len, u8 *membuf, int *membuf_len);
extern int get_04_04_blob(u8 *buf, int len, u8 *membuf, int *membuf_len);

extern int get_00_01_blob(u8 *buf, int buf_len, int *chat_cmd);
extern int get_00_02_blob(u8 *buf, int buf_len, int *uic_crc);
extern int get_00_04_blob(u8 *buf, int buf_len, int *expire_time);
extern int get_00_09_blob(u8 *buf, int buf_len, int *created_time);

extern char * REMOTE_MSG;
extern uint global_unknown_cmd24_time_sec;


miracl *mip;

char user_pubkey[0x81];

extern char skype_pub[0x100+1];

struct pubkey {
	char credentials[0x105];
	char user_pubkey[0x81];
	int UIC_CRC;
};

//
// public key to 'unsgin' signed data
//
//themagic_pub[0x80+1]=


struct pubkey pubkeys_db[10] = { 
//cert1
	{
"\x00\x00\x00\x01\xA6\x60\x57\xB4\xC5\x2B\x48\x0C\xBA\xF6\x0D\x1F"
"\x60\xCD\xFD\x53\xCA\x42\x40\x54\x47\x73\x03\xDD\x7D\xE9\x9B\x76"
"\x40\xA5\x34\x7E\xE0\x72\x23\x7D\x21\x4A\x68\x10\xE3\xD6\x78\x2D"
"\xDB\x3E\xFB\xDA\x71\xE9\x13\x8D\xF1\xDC\x9B\x04\x03\x00\x8F\x4F"
"\x04\xA5\x44\xBE\x33\xFD\xF1\xE9\xB3\xC1\xBB\xB7\xDE\x08\x58\xD1"
"\x98\x24\x30\xFA\x50\xE8\x91\xAE\xC5\xD0\x20\xDA\x8D\x54\x3C\xEB"
"\xC7\x8F\x16\x22\x4D\xE8\x59\xCB\xEB\xED\x56\xA2\xCE\xDF\xD2\xA6"
"\xB6\xA4\xAB\xCA\x36\x00\x4C\x85\xDB\xE4\x44\x6A\x6A\xD7\x19\x7B"
"\xA5\x33\xF4\x03\xAC\x0C\x68\x81\x51\xFC\xAF\x47\x8B\x5A\x18\x78"
"\x76\x04\xF4\xA5\xD9\x49\x96\x6A\x96\x0E\x8B\xE2\xAB\xF6\xE7\xF2"
"\x3D\xF7\x7B\x11\x82\xBD\x77\x85\xF8\x6D\xDF\xC6\xBA\x9F\xE7\xF3"
"\x6C\x4F\x23\xFB\x76\x6E\xE8\x12\x37\x32\x67\xC2\x92\xC0\x45\x67"
"\x90\xAB\x22\x96\x32\xC2\xFB\x64\x5E\x9D\x7F\x52\x23\x94\x03\xDB"
"\x42\xC1\x55\x83\xF6\x59\xDF\xDF\x6A\x3E\x57\x27\x48\x92\xD4\xBC"
"\xCA\x62\x3E\x46\x68\x02\xBF\x93\x9E\xB3\x2E\xA9\xC9\x06\xE7\x60"
"\xC2\x0B\x33\x40\x45\xAD\x81\x37\x1C\x63\x96\xD2\x45\x7C\x77\xDF"
"\xDF\x41\x85\x61"
,
"\xD8\x81\xDE\x8F\x79\x18\xDD\xFE\x68\x46\x80\xD7\xD0\xEB\x0C\x0A"
"\xAA\xF3\xED\xAC\xA9\xA4\x66\x7B\x7C\xFF\x16\xC3\x5A\x65\xDB\xA9"
"\x7C\xA2\xD6\xB7\x11\xE1\xFF\xA3\xEE\x85\xDF\xF1\x0D\x47\x5E\x31"
"\xE7\xF2\x91\x62\x20\x07\x00\x6B\x18\x31\xB7\x50\xC7\x21\xF4\xCB"
"\x6E\x5E\x51\xCE\xFD\x53\x16\x87\x03\xFB\x2E\xC0\x96\xDD\xFD\x7E"
"\x2D\xB4\xBC\xC4\xA4\x2D\x0E\x52\x9A\x2B\xBE\xCC\x34\xDC\x9C\x17"
"\xEB\xE3\x83\x1F\x55\x13\x75\xFF\xD0\xF1\x08\xA7\x8F\xFF\x81\xD5"
"\xC6\x95\x39\x12\xF0\xF0\x27\xF5\x21\xFA\xD8\x94\x65\x52\xDE\xF5"
,
0x00
	},
// cert2
	{
"\x00\x00\x00\x01\xA7\xCF\xDF\xF5\xA9\x69\x80\x2C\x56\x12\xD5\x8B"
"\x4B\xB1\x6A\x51\x0B\xF4\xE1\x69\x47\x96\x89\x2D\x82\xA2\x16\xB7"
"\x19\xC9\x52\xDF\x08\x84\x0D\x28\x04\x0F\x10\x6F\x07\xD4\xFF\x3E"
"\x64\x80\x34\x36\xDC\x25\x5F\x79\xF1\x7F\x1C\x4C\x90\x9C\x03\xE2"
"\xEF\x9D\xB9\xC6\xD9\x52\x55\xD4\xC0\xFE\x31\x6E\x08\xEA\xFA\xC9"
"\x61\xBB\xF8\xDA\xF7\x2E\x8A\x13\x16\xB2\x12\x7E\x17\x38\xD7\x13"
"\x2E\x85\x1D\x27\x63\x71\xDD\x48\xA9\x95\x37\xF6\xFE\x62\x76\x31"
"\xF8\x0E\x5E\x4B\x1A\x8C\xC2\xF4\x14\x80\x5E\x96\x1C\xCB\x81\xE7"
"\xDC\x5A\xF5\xE7\xD8\x6D\xE7\x9F\xF2\xAD\x77\xA1\xE1\xA4\x03\xCF"
"\x57\x41\xC6\x61\x82\xD8\xBF\x24\x7A\x1F\xC4\x23\x08\xDC\xC2\x5A"
"\x63\x79\x95\xFF\x0B\x3E\x1E\xF8\x7A\x6C\x49\x05\x00\x45\x5E\xDD"
"\xAB\x9F\x19\xF6\x50\xD1\x4A\xB9\x02\x92\xC5\x62\x6E\x27\x44\xDC"
"\x68\x06\x09\xFD\x1D\x6E\xC1\xC0\x0F\x3D\x90\xE4\x1A\xF9\xDE\x46"
"\x5B\x27\xB6\x9F\x48\xAC\xB4\x1A\x95\x92\x8C\x7D\xE2\x9D\xA3\xA7"
"\xC7\x06\x95\x2A\xFC\xD3\x86\xC3\x46\x4E\x7E\x9F\xF8\xA6\x2C\xE9"
"\x5D\x94\xFC\x95\xCC\xC0\x83\x84\xC0\x40\x35\xDD\xA0\x72\x6B\x78"
"\x7C\x26\x3E\x68"
,
"\xD8\x81\xDE\x8F\x79\x18\xDD\xFE\x68\x46\x80\xD7\xD0\xEB\x0C\x0A"
"\xAA\xF3\xED\xAC\xA9\xA4\x66\x7B\x7C\xFF\x16\xC3\x5A\x65\xDB\xA9"
"\x7C\xA2\xD6\xB7\x11\xE1\xFF\xA3\xEE\x85\xDF\xF1\x0D\x47\x5E\x31"
"\xE7\xF2\x91\x62\x20\x07\x00\x6B\x18\x31\xB7\x50\xC7\x21\xF4\xCB"
"\x6E\x5E\x51\xCE\xFD\x53\x16\x87\x03\xFB\x2E\xC0\x96\xDD\xFD\x7E"
"\x2D\xB4\xBC\xC4\xA4\x2D\x0E\x52\x9A\x2B\xBE\xCC\x34\xDC\x9C\x17"
"\xEB\xE3\x83\x1F\x55\x13\x75\xFF\xD0\xF1\x08\xA7\x8F\xFF\x81\xD5"
"\xC6\x95\x39\x12\xF0\xF0\x27\xF5\x21\xFA\xD8\x94\x65\x52\xDE\xF5"
,
0x00
	},
// cert3
{
"\x00\x00\x00\x01\x9D\x0C\x78\x38\x99\x7D\xAF\xFC\x7B\xF9\x10\x22"
"\x90\xE7\x71\xA2\xD1\xE0\x27\xD9\x35\x6A\x80\x74\x1D\xCF\x8A\xBF"
"\xB2\xCD\x06\x2A\x1B\xFD\x40\x95\x6B\x69\x09\xFA\x4D\x11\x5B\x97"
"\x44\x10\x04\xB9\xD9\xA6\x80\x17\xD8\x74\xBF\x18\xFE\x31\xAC\xD3"
"\xB9\x67\xF6\xC1\x31\xE5\x50\x68\xA3\x1D\x89\x09\xC0\xCB\x64\x93"
"\xA4\x08\xE4\x7E\x38\x4C\x92\x01\x74\xC7\x58\x41\x8E\xF0\xA4\x7A"
"\xF2\xC0\xFE\x10\xB6\x6C\x6E\xE4\x05\xCD\xC3\x69\x08\x66\xD9\xF1"
"\x76\xE9\x5C\x0E\x37\x78\x2C\x2C\xE0\x46\x07\xB7\x31\x29\x24\x7D"
"\x2C\xBD\x85\x4A\xE4\xAB\x2C\x59\x63\x09\xF6\xF9\xA0\x26\xBF\xC8"
"\x45\x89\x50\x06\x34\x5C\x5A\x8A\xEC\x86\xE6\x92\x24\x36\xF0\x44"
"\x6C\xD5\x0E\xFE\x4E\xA2\xA7\xE5\x95\x1E\xA7\x00\x13\x34\xAD\x98"
"\x21\xE2\xE5\x69\x77\x24\x0D\x38\xA2\x15\x77\x75\x8B\x17\xC7\xEB"
"\x43\x43\x5E\x56\x78\x41\xCC\x6A\x8A\x39\xD9\xD0\x88\xAF\x81\x6C"
"\x24\x90\x5C\x32\x23\xD2\x2E\x64\x31\xBE\x4A\x4A\x9B\x8C\x52\x6B"
"\x9E\x7D\x1A\x84\x62\x4F\x71\x58\xBE\x71\x4A\x96\xDD\x50\x47\x92"
"\x13\x2E\xAD\xA1\xFB\x86\x05\xDE\xA0\x2B\x85\x04\x57\x7B\x9E\x81"
"\x79\x7C\x65\x95"
,
"\x23\xB1\x6E\x72\xBF\xAA\x69\x0C\x2D\xC6\xBA\x75\x91\xE2\x78\x9B"
"\x72\x14\x75\x73\xB5\x0D\x51\x3C\xD6\xB1\xA5\xC8\x54\x01\x86\x26"
"\x45\x8A\x4A\x46\xCE\x89\xC4\x76\x37\x19\x1E\x4F\x52\xC8\xD1\x53"
"\x30\x76\x0E\xC1\xCF\xA8\x95\x3B\xFF\x7E\x9E\xB7\xDB\x97\x8A\x33"
"\x57\xA9\x84\x3F\x09\xBB\x3E\x12\xAF\x55\x9A\xA5\xFB\xC0\x35\x39"
"\x68\x1D\x55\x1B\x10\xBB\x11\x05\x1B\x3F\x54\x56\xB8\x29\x03\xF9"
"\x32\x78\x6D\x82\xC3\xA8\x3C\x9D\xDD\xF4\xEE\x66\x9D\xB8\x58\x17"
"\xBC\xDC\xAD\xA6\x20\xE5\x41\xBC\xD0\x7D\xD3\xCC\xBB\xFE\xFE\x45"
,
0x00
},
	{
		0x00, 0x00, 0x00
	},
	{
		0x00, 0x00, 0x00
	},
	{
		0x00, 0x00, 0x00
	},

};




int rsa_unsign_profile(char *buf, int len, char *outbuf) {  

    big e,m,kn;
	
	mip=mirsys(100,0);

    e=mirvar(0);
    m=mirvar(0);
    kn=mirvar(0);

    bytes_to_big(0x100,buf,m);
	bytes_to_big(0x100,skype_pub,kn);

	power(m,65537,kn,e);
	
	big_to_bytes (0x100, e, outbuf, TRUE);

    return 0;
}


int rsa_unsign_profile_data(char *buf, int len, char *outbuf) {  

    big e,m,kn;
	
	mip=mirsys(100,0);

    e=mirvar(0);
    m=mirvar(0);
    kn=mirvar(0);

    bytes_to_big(0x80,buf,m);
	bytes_to_big(0x80,user_pubkey,kn);

	power(m,65537,kn,e);
	
	big_to_bytes (0x80, e, outbuf, TRUE);

    return 0;
};


int add_cert(int index, char *credentials, char *pubkey) {
	int UIC_CRC;
	int i;

    // i = 9;
    i = index;

    // fill new slot
	memcpy(pubkeys_db[i].credentials, "\x00\x00\x00\x01", 4);
	memcpy(pubkeys_db[i].credentials+4, credentials, 0x100);

	memcpy(pubkeys_db[i].user_pubkey, pubkey, 0x80);

	UIC_CRC=Calculate_CRC32( (char *)pubkeys_db[i].credentials, 0x104);
	pubkeys_db[i].UIC_CRC = UIC_CRC;

    show_memory(pubkeys_db[i].credentials, 0x104, "new db credentials:");
    show_memory(pubkeys_db[i].user_pubkey, 0x80, "new db user_pubkey:");
    debuglog("%d UIC_CRC = %08X\n", i, UIC_CRC);

	return 0;
};


int init_crypto() {
	int UIC_CRC;
	int i;
	int arr_size;

	arr_size = sizeof(pubkeys_db) / sizeof(pubkeys_db[0]);
	debuglog("Cert array size: %d\n", arr_size);
	
	debuglog("Calculate UIC_CRC for all certs...\n");
	for(i=0;i<arr_size;i++) {
		UIC_CRC=Calculate_CRC32( (char *)pubkeys_db[i].credentials, 0x104);
		pubkeys_db[i].UIC_CRC = UIC_CRC;
		debuglog("%d UIC_CRC = %08X\n", i, UIC_CRC);
	};

	return 0;
};


int decode_signed_text(char *remote_credentials, int remote_credentials_len, char *remote_signblock, int remote_signblock_len){
	u8 outbuf[0x100];
	u8 signed_text[0x200];
	int signed_text_len;
	int i;

	debuglog("Unsigning first 0x100 bytes...\n");
	rsa_unsign_profile(remote_credentials+4,0x100,outbuf);
	show_memory(outbuf,0x100,"unsign cred:");

	debuglog("Extracting pubkey from certificate (credentials)\n");
	// save remote user pubkey
	for(i=0;i<0x100;i++){
		if((outbuf[i]==0x80) && (outbuf[i+1]==0x01)){
			memcpy(user_pubkey,outbuf+i+2,0x80);
		};
	};
	
	show_memory(user_pubkey,0x80,"user pubkey data:");
	
	debuglog("remote credentials:\n");
	main_unpack(outbuf, 0x100);

	do_time_check(outbuf, 0x100);

	debuglog("Unsigning 04-03 signblock 0x80 bytes...\n");
	rsa_unsign_profile_data(remote_signblock,0x80,outbuf);
	show_memory(outbuf,0x80,"unsign data:");

	// need to concate with last bytes after 0x80, and remove sha1 in decrypted.
	signed_text_len = 0;
	
	// remove sha1
	memcpy(signed_text, outbuf, 0x80-0x15);
	signed_text_len += 0x80-0x15;

	// move data (rest of bytes in signblock) right after signed text
	memcpy(signed_text+0x80-0x15, remote_signblock+0x80, remote_signblock_len - 0x80);
	signed_text_len += remote_signblock_len - 0x80;

	debuglog("===\n");
	debuglog("SIGNED TEXT\n");
	debuglog("===\n");

	show_memory(signed_text, signed_text_len, "recovered signed data:");
	main_unpack(signed_text, signed_text_len);

    if (1) {
        unsigned int data_int;

        // extract 00_05 time in sec
		debuglog("::::::::::::::Got Crypto pkt\n");
        data_int = get_00_05_blob(signed_text, signed_text_len);
        if (data_int > 0) {
            debuglog("global_unknown_cmd24_time_sec = 0x%08X\n", data_int);
        };
    };

	return 0;
};


int recovery_signed_data(char *buf41, int buf41_len) {
	int CHAT_CMD;
	int UIC_CRC;
	int i;
	int arr_size;

	char membuf[0x1000];
	int membuf_len;

	char remote_credentials[0x104+1];
	int remote_credentials_len;
	char remote_signblock[0x1000];
	int remote_signblock_len;

	
	init_crypto();


	membuf_len = 0;
	get_04_04_blob(buf41, buf41_len, membuf, &membuf_len);
	main_unpack(membuf, membuf_len);


	CHAT_CMD = 0;
	get_00_01_blob(membuf, membuf_len, &CHAT_CMD);
	debuglog("CHAT_COMMAND: 0x%02X\n", CHAT_CMD);

	if (CHAT_CMD == 0){
		debuglog("No found 00-01 blob with CHAT_COMMAND!\n");
		return -1;
	};

	// chatsign or headersign
	if ((CHAT_CMD == 0x24) || (CHAT_CMD == 0x2A)){
		remote_signblock_len = 0;
		get_04_03_blob(membuf, membuf_len, remote_signblock, &remote_signblock_len);
		debuglog("Remote signblock len: 0x%08X\n", remote_signblock_len);

		remote_credentials_len = 0;
		get_04_04_blob(membuf, membuf_len, remote_credentials, &remote_credentials_len);
		debuglog("Remote credentials len: 0x%08X\n", remote_credentials_len);
	} else {

		if (CHAT_CMD == 0x2B){
			// msgsign
			// get uic_crc from blob, cmp with our base
			// make struct-es { char *pubkey, uic_crc } etc...
			UIC_CRC = 0;
			get_00_02_blob(membuf, membuf_len, &UIC_CRC);
			debuglog("UIC_CRC: 0x%08X\n", UIC_CRC);
			debuglog("Credentials CRC: 0x%08X\n", pubkeys_db[0].UIC_CRC);

			arr_size = sizeof(pubkeys_db) / sizeof(pubkeys_db[0]);
			debuglog("Cert array size: %d\n", arr_size);
			
			remote_credentials_len = 0;

			debuglog("Try to find needed keys...\n");

			for(i=0;i<arr_size;i++) {

				debuglog("%d\n",i);
                debuglog("Test UIC: 0x%08X\n", pubkeys_db[i].UIC_CRC);

				if (pubkeys_db[i].UIC_CRC == UIC_CRC){
					debuglog("Cert found!\n");
					debuglog("Cert index: %d\n", i);
					debuglog("UIC_CRC: 0x%08X\n", UIC_CRC);
					// fill remote_credentials
					memcpy(remote_credentials, pubkeys_db[i].credentials, 0x104);
					remote_credentials_len = 0x104;
					break;
				};
			};
			if (remote_credentials_len == 0) {
				debuglog("ERROR: Cert not found!\n");
				debuglog("Needed UIC_CRC: 0x%08X\n", UIC_CRC);
				return -1;
			};
			
			// fill remote_signblock
			remote_signblock_len = 0;
			get_04_03_blob(membuf, membuf_len, remote_signblock, &remote_signblock_len);
			debuglog("Remote signblock len: 0x%08X\n", remote_signblock_len);

		} else {
			// unknown command (not signed data)
			debuglog("CHAT_COMMAND unknow: 0x08X\n", CHAT_CMD);
			return -1;
		};

	};
	

	decode_signed_text(remote_credentials, remote_credentials_len, remote_signblock, remote_signblock_len);


	return 0;
};


int recovery_signed_data2(char *buf41, int buf41_len) {
	int CHAT_CMD;
	int UIC_CRC;
	int i;
	int arr_size;

	char membuf[0x1000];
	int membuf_len;

	char remote_credentials[0x104+1];
	int remote_credentials_len;
	char remote_signblock[0x1000];
	int remote_signblock_len;

    int blobs_count;
	int ret;
	
	init_crypto();


	membuf_len = 0;
	get_04_04_blob(buf41, buf41_len, membuf, &membuf_len);
	main_unpack(membuf, membuf_len);


	CHAT_CMD = 0;
	get_00_01_blob(membuf, membuf_len, &CHAT_CMD);
	debuglog("CHAT_COMMAND: 0x%02X\n", CHAT_CMD);

	if (CHAT_CMD == 0){
		debuglog("No found 00-01 blob with CHAT_COMMAND!\n");
		return -1;
	};

	// chatsign or headersign
	if ((CHAT_CMD == 0x24) || (CHAT_CMD == 0x2A)){
		remote_signblock_len = 0;
		get_04_03_blob(membuf, membuf_len, remote_signblock, &remote_signblock_len);
		debuglog("Remote signblock len: 0x%08X\n", remote_signblock_len);

		remote_credentials_len = 0;
		get_04_04_blob(membuf, membuf_len, remote_credentials, &remote_credentials_len);
		debuglog("Remote credentials len: 0x%08X\n", remote_credentials_len);
	} else {

		if (CHAT_CMD == 0x2B){
			// msgsign
			// get uic_crc from blob, cmp with our base
			// make struct-es { char *pubkey, uic_crc } etc...
			UIC_CRC = 0;
			get_00_02_blob(membuf, membuf_len, &UIC_CRC);
			debuglog("UIC_CRC: 0x%08X\n", UIC_CRC);
			debuglog("Credentials CRC: 0x%08X\n", pubkeys_db[0].UIC_CRC);

			arr_size = sizeof(pubkeys_db) / sizeof(pubkeys_db[0]);
			debuglog("Cert array size: %d\n", arr_size);
			
			remote_credentials_len = 0;

			debuglog("Try to find needed keys...\n");

			for(i=0;i<arr_size;i++) {

				debuglog("%d\n",i);
                debuglog("Test UIC: 0x%08X\n", pubkeys_db[i].UIC_CRC);

				if (pubkeys_db[i].UIC_CRC == UIC_CRC){
					debuglog("Cert found!\n");
					debuglog("Cert index: %d\n", i);
					debuglog("UIC_CRC: 0x%08X\n", UIC_CRC);
					// fill remote_credentials
					memcpy(remote_credentials, pubkeys_db[i].credentials, 0x104);
					remote_credentials_len = 0x104;
					break;
				};
			};
			if (remote_credentials_len == 0) {
				debuglog("ERROR: Cert not found!\n");
				debuglog("Needed UIC_CRC: 0x%08X\n", UIC_CRC);
				return -1;
			};
			
			// fill remote_signblock
			remote_signblock_len = 0;

            blobs_count = get_04_03_blob_count(membuf, membuf_len);
            for (i=0;i<blobs_count;i++) {
                remote_signblock_len = 0;
                ret = get_04_03_blob_one(membuf, membuf_len, remote_signblock, &remote_signblock_len, i);
                if (ret) {
                    debuglog("i = %d\n",i);
                    debuglog("remote_signblock_len = %d\n", remote_signblock_len);
                    decode_signed_text(remote_credentials, remote_credentials_len, remote_signblock, remote_signblock_len);
                };
            };

            return 1;

		} else {
			// unknown command (not signed data)
			debuglog("CHAT_COMMAND unknow: 0x08X\n", CHAT_CMD);
			return -1;
		};

	};
	
	decode_signed_text(remote_credentials, remote_credentials_len, remote_signblock, remote_signblock_len);

	return 0;
};


int recovery_signed_data3(char *membuf, int membuf_len) {
	int CHAT_CMD;
	int UIC_CRC;
	int i;
	int arr_size;

	char remote_credentials[0x104+1];
	int remote_credentials_len;
	char remote_signblock[0x1000];
	int remote_signblock_len;

    int blobs_count;
	int ret;
	
	init_crypto();


	//main_unpack(membuf, membuf_len);


	CHAT_CMD = 0;
	get_00_01_blob(membuf, membuf_len, &CHAT_CMD);
	debuglog("CHAT_COMMAND: 0x%02X\n", CHAT_CMD);

	if (CHAT_CMD == 0){
		debuglog("No found 00-01 blob with CHAT_COMMAND!\n");
		return -1;
	};

	// chatsign or headersign
	if ((CHAT_CMD == 0x24) || (CHAT_CMD == 0x2A)){
		remote_signblock_len = 0;
		get_04_03_blob(membuf, membuf_len, remote_signblock, &remote_signblock_len);
		debuglog("Remote signblock len: 0x%08X\n", remote_signblock_len);

		remote_credentials_len = 0;
		get_04_04_blob(membuf, membuf_len, remote_credentials, &remote_credentials_len);
		debuglog("Remote credentials len: 0x%08X\n", remote_credentials_len);
	} else {

		if (CHAT_CMD == 0x2B){
			// msgsign
			// get uic_crc from blob, cmp with our base
			// make struct-es { char *pubkey, uic_crc } etc...
			UIC_CRC = 0;
			get_00_02_blob(membuf, membuf_len, &UIC_CRC);
			debuglog("UIC_CRC: 0x%08X\n", UIC_CRC);
			debuglog("Credentials CRC: 0x%08X\n", pubkeys_db[0].UIC_CRC);

			arr_size = sizeof(pubkeys_db) / sizeof(pubkeys_db[0]);
			debuglog("Cert array size: %d\n", arr_size);
			
			remote_credentials_len = 0;

			debuglog("Try to find needed keys...\n");

			for(i=0;i<arr_size;i++) {

				debuglog("%d\n",i);
                debuglog("Test UIC: 0x%08X\n", pubkeys_db[i].UIC_CRC);

				if (pubkeys_db[i].UIC_CRC == UIC_CRC){
					debuglog("Cert found!\n");
					debuglog("Cert index: %d\n", i);
					debuglog("UIC_CRC: 0x%08X\n", UIC_CRC);
					// fill remote_credentials
					memcpy(remote_credentials, pubkeys_db[i].credentials, 0x104);
					remote_credentials_len = 0x104;
					break;
				};
			};
			if (remote_credentials_len == 0) {
				debuglog("ERROR: Cert not found!\n");
				debuglog("Needed UIC_CRC: 0x%08X\n", UIC_CRC);
				return -1;
			};
			
			// fill remote_signblock
			remote_signblock_len = 0;

            blobs_count = get_04_03_blob_count(membuf, membuf_len);
            for (i=0;i<blobs_count;i++) {
                remote_signblock_len = 0;
                ret = get_04_03_blob_one(membuf, membuf_len, remote_signblock, &remote_signblock_len, i);
                if (ret) {
                    debuglog("i = %d\n",i);
                    debuglog("remote_signblock_len = %d\n", remote_signblock_len);
                    decode_signed_text(remote_credentials, remote_credentials_len, remote_signblock, remote_signblock_len);
                };
            };

            return 1;

		} else {
			// unknown command (not signed data)
			debuglog("CHAT_COMMAND unknow: 0x08X\n", CHAT_CMD);
			return -1;
		};

	};
	
	decode_signed_text(remote_credentials, remote_credentials_len, remote_signblock, remote_signblock_len);

	return 0;
}
