// miramax.c : Defines the entry point for the console application.
//

/*
 *   Program to encode text using RSA public key.
 *
 *   *** For Demonstration use only *****
 *
 *   Copyright (c) 1988-1997 Shamus Software Ltd.
 */


#include <stdio.h>

#include "miracl_lib/miracl.h"
#include <stdlib.h>
#include <string.h>

#include "crypto/md5.h"

#include "skype/skype_basics.h"

extern int show_memory(char *mem, int len, char *text);

extern miracl *mip;

extern char skype_pub[0x100+1];


typedef unsigned char		u8;
typedef unsigned short		u16;
typedef unsigned long		u32;
typedef unsigned long long	u64;


struct bigtype	skype_384_bit_dh_mod = {12, skype_384_bit_dh_modulus};	// Skype 384-bit DH session key modulus

static void reverse_bytes (void *x, const u32 dwords)
{
	u32		i, j;
	
	for (i = 0; i < dwords*2; i += 4)
		j = dword(x,i), dword(x,i) = _bswap32(dword(x,dwords*4-4-i)), dword(x,dwords*4-4-i) = _bswap32(j);
}


//u32					supernode_iv2[13];
u32					supernode_iv2[24+1];


u32					buffer[64];	// 256 bytes, just in case, but 192 should most probably suffice
struct bigtype		dh384_sec = {12, supernode_iv2}, dh384_pub = {0, buffer};
MD5_state			md5 = MD5_INIT;

u32 Skype_Handshake (char *output, int *len) {
	u32					i, j, n, length;
	


	//big m;
	//mip=mirsys(100,0);
	//m=mirvar(2);
	
	
	// generate a random 384-bit number A = local secret key
	for (i = 0; i < 12; i++) srand32(), dh384_sec.w[i] = rand32(); 
	dh384_sec.w[11] &= 0x7FFFFFFF;	
	dh384_sec.w[12] = 0;

	// 2^A = local public key
	powltr (2, &dh384_sec, &skype_384_bit_dh_mod, &dh384_pub);
	reverse_bytes (dh384_pub.w, 12);

	show_memory(dh384_pub.w, 0x30, "RSA_crypted_first_DH_pkt_and_key");

	// adding some random garbage [almost] the way Skype does it
	for (i = 12; i < 24; i++) srand32(), dh384_pub.w[i] = rand32();
	n = 48 + rand32() % 49;	

	/*
	for (i = 12; i < 24; i++) srand32(), dh384_pub.w[i] = rand32();
	n = 48 + rand32()%49;	// adding some random garbage [almost] the way Skype does it
	*/

	/*
	memcpy(output, (char *)dh384_pub.w, 0x30);
	memcpy(output+0x30, "\xBF\x64\x85\xF2\x3B\xB0\x61\x1E\x77\xBC\xFD\x0A\x73\x88\x59\xB6\x2F\x14\x75\x22\xAB\x60\x51\x4E\xE7\x6C\xED\x3A\xE3\x38\x49\xE6", 0x20);
	n=0x30+0x20;
	*/

	memcpy(output, (char *)dh384_pub.w, n);
	*len = n;

	return 0;
};

u32 Skype_Handshake2_powmod (char *input, int len, char *output, char *output2) {
	u32					i, j, n, length;
	char somebuf[0x1000];

	
	memcpy(buffer, input, len);

	// calculate 2^B^A = 2^A^B = common secret key
	reverse_bytes (buffer, 12);
	j = dword(buffer,48), dword(buffer,48) = 0;

	// result goes straight into iv2
	powmod ( &dh384_pub, &dh384_sec, &skype_384_bit_dh_mod, &dh384_sec);
	reverse_bytes (dh384_sec.w, 12);
	dword(buffer,48) = j;

	// exchange 64-bit MD5 hashes of the common key
	MD5_init (&md5);
	MD5_update (&md5, "O", 1);
	MD5_update (&md5, dh384_sec.w, 48);
	MD5_end (&md5);

	memcpy(output, (char *)md5.hash, 8);

	// for compare recv data
	MD5_init (&md5);
	MD5_update (&md5, "I", 1);
	MD5_update (&md5, dh384_sec.w, 48);
	MD5_end (&md5);

	memcpy(output2, (char *)md5.hash, 8);

	memcpy(somebuf, dh384_sec.w, 48);
	extconn_Crypto_genkey(somebuf);

	return 0;
};


