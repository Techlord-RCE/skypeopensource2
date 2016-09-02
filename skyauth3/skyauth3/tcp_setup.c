/*  
*
* Direct TCP connect to skype client
*
*/


#include "skype/skype_basics.h"
#include "skype/skype_rc4.h"

#include "short_types.h"

extern int sock;

// socket comm
extern int udp_talk(char *remoteip, unsigned short remoteport, char *buf, int len, char *result);
extern int tcp_talk(char *remoteip, unsigned short remoteport, char *buf, int len, char *result,int need_close);
extern int tcp_talk_recv(char *remoteip, unsigned short remoteport, char *result, int need_close);
extern int tcp_talk_send(char *buf, int len);

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


u8 aes_key[0x20];


extern u32 Skype_Handshake(char *out, int *n);
extern u32 Skype_Handshake2_powmod (char *input, int len, char *output, char *output2);


unsigned int make_dh384_handshake(char *ip, unsigned short port){
	u8 result[0x1000];
	char *pkt;
	int send_len;
	int len;
	char *bufhash;
	char *cmphash;

	pkt=malloc(0x1000);


	Skype_Handshake(pkt, &send_len);
	
	printf("Handshake v5.5 1 pkt len: 0x%08X\n",send_len);

	// Display pkt before sending
	show_memory(pkt, send_len, "Send pkt");

	// Sending packet
	len=tcp_talk(ip,port,pkt,send_len,result,0);
	if (len<=0) {
		printf("recv timeout\n");
		exit(1);
	};
	if (len>=1023) {
		printf("Recv len: 0x%08X\n",len);
		printf("Too big pkt recv, exiting...\n");
		exit(1);
	};


	// Display received pkt
	show_memory(result, len, "Result");

	bufhash=malloc(0x100);
	cmphash=malloc(0x100);
	Skype_Handshake2_powmod(result, len, bufhash, cmphash);

	show_memory(bufhash, 8, "MD5 SEND Hash");
	show_memory(cmphash, 8, "MD5 for compare Hash (should be)");
	
	// Sending 2-nd packet with hash
	tcp_talk_send(bufhash,8);

	return 0;
}

