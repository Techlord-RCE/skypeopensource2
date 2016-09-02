#include "skype/skype_rc4.h"

// for aes
#include "crypto/rijndael.h"

// for 41 
#include "decode41.h"


extern	RC4_context rc4_send;
extern	RC4_context rc4_recv;

// dh-384 bit functions


//
//
//


extern u32 Skype_Handshake(char *out, int *n);
extern u32 Skype_Handshake2_powmod (char *input, int len, char *output, char *output2);

//unsigned int showme_rc4(char *result, int len);

extern u32 supernode_iv2[13];

//
// I/O IVs, probably no need to save
//
u32	supernode_ivi, supernode_ivo;	


#define bswap16(x)			((((x)>>8)&0xFF)+(((x)&0xFF)<<8))


// decodes a 32-bit dword from a 7-bit sequence, 
// returns the number of decoded bytes

static u32 decode32 (u32 * const to, const u8 * const from, const u32 bytes)
{
	u32		i, a;
	
	for (i = 0, a = 0; i < bytes; i++)
	{
		a |= (from[i] & 127) << (i*7);
		if (from[i] <= 127)
		{
			*to = a;	// length ok
			return i+1;
		}
	}
	*to = 0x80000000;	// really invalid length, ran out of input
	return i+1;
}


#define byte1(x,n)			(*(u8*)(((u8*)(x))+(n)))
#define word1(x,n)			(*(u16*)(((u8*)(x))+(n)))
#define dword1(x,n)			(*(u32*)(((u8*)(x))+(n)))
#define qword1(x,n)			(*(u64*)(((u8*)(x))+(n)))



int make_dh384_handshake(char *ip, unsigned short port){
	u8 result[0x1000];
	u8 result2[0x1000];
	u8 recvbuf[0x1000];
	u32 recvlen;
	char *pkt;
	int send_len;
	int len;
	int len2;
	char *bufhash;
	char *cmphash;
	int n;
	unsigned int j_global;

	u32	buffer[64];
	u32	buffer2[64];

	int i,j;

// common DH-384 key, probably no need to save
//	u32					supernode_iv2[13];	

	u8					*supernode_data;		// leftovers
	u32					supernode_bytes;		// left from the last packet
	u8					*supernode_last_data;	// position of the last returned command to be removed
	u32					supernode_last_bytes;	// size of the last returned command with its header
	u32					supernode_idi, supernode_ido;	// I/O packet sequence numbers


	//memset (&supernode, 0, sizeof (supernode));	// absolutely necessary

	memset (&buffer, 0x00, sizeof (buffer));
	memset (&buffer2, 0x00, sizeof (buffer2));

    debuglog("Sizeof buffer: 0x%08X\n", sizeof (buffer));


	supernode_ivi=0;
	supernode_ivo=0;
	supernode_last_bytes=0;
	supernode_idi=0;
	supernode_ido=0;

    supernode_bytes = 0;
    supernode_data = NULL;

	pkt=malloc(0x1000);

    memset(pkt, 0x00, 0x1000);

    Skype_Handshake_init();

    rc4_send.i = 0;
    rc4_send.j = 0;
    memset(rc4_send.s, 0x00, 256);

    rc4_recv.i = 0;
    rc4_recv.j = 0;
    memset(rc4_recv.s, 0x00, 256);

    for(i=0;i<13;i++){
        debuglog("supernode_iv2[%d]: 0x%08X\n",i, supernode_iv2[i]);
    };


	Skype_Handshake(pkt, &send_len);
	
	debuglog("Handshake v5.5 1 pkt len: 0x%08X\n",send_len);

	// Display pkt before sending
	show_memory(pkt, send_len, "Send pkt");

	// Sending packet
	len=tcp_talk(ip,port,pkt,send_len,result,0);
	if (len<=0) {
		debuglog("recv timeout\n");
		return -1;
	};
	if (len>=0x1000) {
		debuglog("Recv len: 0x%08X\n",len);
		debuglog("Too big pkt recv, do return...\n");
		return -1;
	};

    
	// Display received pkt
	show_memory(result, len, "Result");

	bufhash=malloc(0x100);
    memset(bufhash, 0x00, 0x100);
	cmphash=malloc(0x100);
    memset(cmphash, 0x00, 0x100);

	Skype_Handshake2_powmod(result, len, bufhash, cmphash);

	show_memory(bufhash, 8, "MD5 SEND Hash");
	show_memory(cmphash, 8, "MD5 CMP Hash");


	// Sending 2-nd packet with hash
	len=tcp_talk(ip,port,bufhash,8,result,0);
	if (len<=0) {
		debuglog("recv timeout\n");
		return -1;
	};
	if (len>=0x1000) {
		debuglog("Recv len: 0x%08X\n",len);
		debuglog("Too big pkt recv, do return...\n");
		return -1;
	};


	// Display received pkt
	show_memory(result, len, "Send 2 hash pkt Result:");


	//i = 0;
	//if (memcmp (&byte(buffer,i), md5.hash, 8)) { /* breakpoint("16"); */ return -1; }		// must receive the hash now

	// must wait for the random bytes
	//n = recv (supernode->s, (char *)buffer, sizeof(buffer), 0);	

	// Sending packet with hash
	len2=tcp_talk_recv(ip,port,result2,0);
	if (len2<=0) {
		debuglog("recv timeout\n");
		return -1;
	};
	if (len2>=0x1000) {
		debuglog("Recv len: 0x%08X\n",len);
		debuglog("Too big pkt recv, do return...\n");
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


		supernode_ivi = bswap32(dword1(buffer,i));
		Skype_RC4_Expand_IV (supernode_ivi, &supernode_iv2[0], &rc4_recv, 1, 48);
		i += 4, n -= 4;

		RC4_crypt (&byte1(buffer,i), 10, &rc4_recv, 1);
		

		// Display received pkt
		//show_memory(&byte(buffer,i+2), 8, "cmp handshake:");

		show_memory(&byte(buffer,i), 10, "cmp handshake:");

		// did not decrypt, never seen anything other than this, although it could be \0\0\0\x\0\0\0\3 where x=0..3
		if (memcmp (&byte(buffer,i+2), "\0\0\0\1\0\0\0\x0F", 8)) { 
			//debuglog("breakpoint18\n");
			//return -1;

    		if (memcmp (&byte(buffer,i+2), "\0\0\0\1\0\0\0\x03", 8)) { 
    			debuglog("breakpoint18_1\n");
    			return -1;
    		};

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
		debuglog("Decoded j (seq num): %d\n",j);

		// the packet is larger than what we have, should recv the rest
		if (j + length/2 > n) { 
			debuglog("breakpoint19\n");
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

		debuglog("size mismatch\n");

	};


    //
    //make own handshake pkt
    //


	//memcpy( (char *)buffer2, (char *)buffer, len2);

	memset((char *)buffer2, 0x00, 48);

	//supernode_ivo = 0x11223344;
	supernode_ivo = rand32();
	
	// every packet has its own IV
	dword(buffer2,0) = _bswap32(supernode_ivo);

    // for same sequence after start
    // or will be bugged in some strange times
    //srand32();

	// sending a random amount of random garbage almost the way skype does it
    // should be always >= 8

	//n = 17;
	n = rand32()%45+14;

    debuglog("n = %d\n", n);

	// packet sequence number
	//supernode_ido = 0x48F9;
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
	
	show_memory(&byte(buffer2,0), n+16, "3 pkt buffer bef:");
	
	RC4_crypt (&byte(buffer2,4), 10, &rc4_send, 1);
	RC4_crypt (&byte(buffer2,14), n+2, &rc4_send, 0);
	
	show_memory(&byte(buffer2,0), n+16, "3 pkt buffer aft rc4:");

	show_memory(buffer2, n+16, "Send pkt3");

	// Sending 3 packet 
	len=tcp_talk_send((char *)buffer2,n+16);
	if (len<0) {
		debuglog("dh384 send pkt3 error\n");
		return -1;
	};

	// Display received pkt
	show_memory(result, len, "Now, 4 recv pkt Result:");

	//return j_global;

    return 1;
}

