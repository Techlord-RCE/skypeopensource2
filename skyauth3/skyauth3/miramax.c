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


extern char xoteg_pub[0x80+1];
extern char xoteg_sec[0x80+1];
extern char skype_pub[0x100+1];
extern char remote_pubkey[0x80];


// Skype 384-bit DH session key modulus
struct bigtype	skype_384_bit_dh_mod = {12, skype_384_bit_dh_modulus};	


static void reverse_bytes (void *x, const u32 dwords) {
	u32		i, j;
	
	for (i = 0; i < dwords*2; i += 4)
		j = dword(x,i), dword(x,i) = _bswap32(dword(x,dwords*4-4-i)), dword(x,dwords*4-4-i) = _bswap32(j);
}


u32					supernode_iv2[13];
u32					buffer[64];	

struct bigtype		dh384_sec = {12, supernode_iv2}, dh384_pub = {0, buffer};


u32 Skype_Handshake (char *output, int *len) {
	u32					i, j, n, length;

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

	memcpy(output, (char *)dh384_pub.w, n);
	*len = n;
	
	return 0;
};


u32 Skype_Handshake2_powmod (char *input, int len, char *output, char *output2) {
	u32					i, j, n, length;
	char somebuf[0x1000];
	MD5_state			md5 = MD5_INIT;
	
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

	extconn_rc4_crypto_genkey(somebuf);

	return 0;
};


int rsa_unsign_cred(char *buf, int len, char *outbuf) {  

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





int rsa_sign(char *buf, int len, char *outbuf)
{  

    big e,m,kd,kn;

	mip=mirsys(100,0);

    e=mirvar(0);
    m=mirvar(0);
    kd=mirvar(0);
    kn=mirvar(0);


    bytes_to_big(0x80,buf,m);
    bytes_to_big(0x80,xoteg_sec,kd);
	bytes_to_big(0x80,xoteg_pub,kn);

    powmod(m,kd,kn,e);

	
	big_to_bytes (0x80, e, outbuf, TRUE);


    return 0;
}





int rsa_decode(char *buf, int len, char *outbuf)
{  

    big e,m,kd,kn;

    
	mip=mirsys(100,0);

    e=mirvar(0);
    m=mirvar(0);
    kd=mirvar(0);
    kn=mirvar(0);


    bytes_to_big(0x80,buf,m);
    bytes_to_big(0x80,xoteg_sec,kd);
	bytes_to_big(0x80,xoteg_pub,kn);

    powmod(m,kd,kn,e);
	
	big_to_bytes (0x80, e, outbuf, TRUE);



    return 0;
}


int rsa_encode(char *buf, int len, char *outbuf)
{
    big e,m,ke;

    mip=mirsys(100,0);

    e=mirvar(0);
    m=mirvar(0);
    ke=mirvar(0);
 

	bytes_to_big(0x80,remote_pubkey,ke);    
    bytes_to_big(0x80,buf,m);

	power(m,65537,ke,e);
	
	big_to_bytes (0x80, e, outbuf, TRUE);


    return 0;
};


/*
int rsa_unsign()
{  

    big e,m,kn;

	char result[0x80];

	char signed_text[]=
"\x2E\x61\x96\xC4\x6F\x57\xB3\xA1\xE8\x0D\xA3\x9A\x3A\x1E\xBC\xE2"
"\x85\xFE\xBB\x08\x29\xE5\xC4\xD3\x68\x0D\xB2\x58\x16\x6F\x44\xAA"
"\x1F\x46\xD3\x18\xA5\x8A\x6B\xBE\xE3\x53\x03\x6A\x8E\xC0\xB7\xCB"
"\x9B\x9A\x7C\xDC\xED\xB7\xCA\x67\x3F\xB9\x9B\x5A\xC4\x2C\x9F\x98"
"\x81\xEA\xCF\x0A\x7D\x6A\xD9\xA7\x97\x70\x56\x5C\x13\x56\x06\x06"
"\xBF\x1C\x8E\x8B\x29\xB5\x10\x12\x47\x02\xA4\x33\xEE\x06\xF2\x43"
"\x3C\xAE\x75\xF0\x40\xF7\xF6\x8C\xAE\x23\x0B\x2D\x9D\xDB\xFB\x37"
"\x18\x5F\xC3\xE1\x89\xAA\x2F\xDE\xE2\xB6\xF4\x84\xD8\x4B\x64\xC8"
;

	
	mip=mirsys(100,0);

    e=mirvar(0);
    m=mirvar(0);
    kn=mirvar(0);


    bytes_to_big(0x80,signed_text,m);
	bytes_to_big(0x80,xoteg_pub,kn);


	power(m,65537,kn,e);
	
	big_to_bytes (0x80, e, result, TRUE);

	show_memory(result,0x80,"data:");



	printf("message ends\n");

    return 0;
}
*/


/*
int rsa_encode_example()
{
    big e,m,ke;

	char result[0x80];


	char clear_text[]=
"\x01\x49\xCF\x36\x4D\x70\x07\xEA\xD1\x10\x91\xCD\xE3\xE5\x96\x67"
"\x29\x49\xCF\x36\x4D\x70\x07\xEA\xD1\x10\x91\xCD\xE3\xE5\x96\x67"
"\x29\x49\xCF\x36\x4D\x70\x07\xEA\xD1\x10\x91\xCD\xE3\xE5\x96\x67"
"\x29\x49\xCF\x36\x4D\x70\x07\xEA\xD1\x10\x91\xCD\xE3\xE5\x96\x67"
"\x29\x49\xCF\x36\x4D\x70\x07\xEA\xD1\x10\x91\xCD\xE3\xE5\x96\x67"
"\x29\x49\xCF\x36\x4D\x70\x07\xEA\xD1\x10\x91\xCD\xE3\xE5\x96\x67"
"\x29\x49\xCF\x36\x4D\x70\x07\xEA\xD1\x10\x91\xCD\xE3\xE5\x96\x67"
"\x29\x49\xCF\x36\x4D\x70\x07\xEA\xD1\x10\x91\xCD\xE3\xE5\x96\x67"
;




    mip=mirsys(100,0);

    e=mirvar(0);
    m=mirvar(0);
    ke=mirvar(0);
 

	bytes_to_big(0x80,xoteg_pub,ke);    
    bytes_to_big(0x80,clear_text,m);

	power(m,65537,ke,e);
	
	big_to_bytes (0x80, e, result, TRUE);

	show_memory(result,0x80,"data:");

    return 0;
}   
*/


/*
int main_crypto(int argc, char* argv[])
{


	//rsa_encode();
	//rsa_decode();
	rsa_sign();

	//rsa_unsign();


	printf("Hello World!\n");

	return 0;
}
*/



