/*\
|*|
|*| Skype Login v0.103 by Sean O'Neil.
|*| Copyright (c) 2009 by VEST Corporation.
|*| All rights reserved. Strictly Confidential!
|*|
|*| Includes: Password Login, User Registration
|*|
|*| Date: 08.07.2009
|*|
\*/

#include <string.h>

#include "skype/skype_basics.h"
#include "skype/skype_rc4.h"

#include "miracl_lib/miracl.h"

#include "crypto/md5.h"
#include "crypto/sha1.h"
#include "crypto/rijndael.h"


// global data
extern RC4_context rc4_send;
extern RC4_context rc4_recv;

extern int sock;


u8 LOCAL_NAME[0x100];
u8 LOCAL_AUTH_BUF[0x11];
u8 CLIENT_VERSION[0x100] = "0/6.16.0.10//";

u8 PUBLIC_KEY[0x81] = 
"\xB2\xC7\xB3\xBF\xC3\x0D\xD7\x51\x01\x4B\x89\x18\x1E\xE3\x3C\x51"
"\x81\x5D\xC6\x3B\xF3\x8A\x84\xDA\x9C\x81\x97\x55\xA9\x44\xCA\xCF"
"\xFE\x51\xDC\xF7\x05\xC1\xF4\x7D\x8D\x75\x86\x44\x37\x3B\xC2\x26"
"\x2D\xB2\xC5\xBF\x02\xDC\x96\xB4\x34\x3F\x2C\x0E\xA5\xFE\xAE\x92"
"\x8C\xBF\x70\x8F\x7D\xE6\x79\xB5\x9A\x5B\x42\xD8\x16\x60\xEA\xA1"
"\xFB\x66\x10\x3B\x61\xA2\xCE\x9C\x4E\xAB\x3A\x63\x00\xF1\xC2\x26"
"\xBF\x1C\xCB\xCE\x7E\xAC\x66\xBB\x59\x6B\x16\xB4\x85\x8F\xF7\xB9"
"\x85\xCB\xC4\x20\xBC\x67\xEA\x32\x36\x56\xF8\xFC\xFA\x8D\x42\xB5"
;


void AES_CTR (const u32 *key, u8 *pkt, const u32 bytes, const u32 IV);

u32				Skype_Login_RSA_Key[48] =
{
	0xBA29700B,0xB57250D7,0x55AAA3A4,0x335A48C9,0xF51DA404,0xCA8F4446,0x31CC2BC4,0xA6C8F1FF,
	0xA2007ACF,0xC8E25638,0xDD2D8732,0xAFD95B80,0xC873E95C,0x3D4C2625,0x1A3EAB16,0x99492AA6,
	0x97CED2E1,0xB7138523,0x6C0375EE,0x8202C61C,0x66B23E1F,0x093AC6EE,0x385EF5F4,0xAD0A804F,
	0x78627651,0xAC550B39,0x0E7A9EAF,0xA4C35289,0xEDB35DCB,0x40468CF0,0xCD9914E5,0x140CA82C,
	0xC88B3CAE,0x96350989,0x692015E7,0x9484B597,0xC0E5ABE0,0x7752A248,0xC72E53EF,0x5D74A14C,
	0xEC983AAB,0xEC87304A,0x6C1AF0FB,0x532A72DF,0x310B0B21,0x1EF1CA5E,0x2F4F5FC8,0xA8F22361
};



u32 encode32 (u8 * const to, const u32 * const from, const u32 words)
{
	u32		n = 0, i, a;
	
	for (i = 0; i < words; i++) { for (a = from[i]; a > 0x7F; a >>= 7, n++) to[n] = (u8) a | 0x80; to[n++] = (u8) a; }
	return n;
}

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

#define attach(x,y,z)	(memcpy(x,y,z),(u32)z)


// 128 bit (16 byte) MD5
u32 MD5_Skype_Password (const char *username, const char *password, u8 *hash128)
{
	MD5_state		skyper = MD5_INIT;
	
	MD5_update (&skyper, username, (u32) strlen (username));
	MD5_update (&skyper, "\nskyper\n", 8);
	MD5_update (&skyper, password, (u32) strlen (password));
	MD5_end (&skyper);
	memcpy (hash128, skyper.hash, 16);
	return 16;
}


// key256 -- outpub buf
// encrypted_key1536 -- outpub buf
int Produce_Session_Key ( const u32 *rand192, u32 *key256, u32 *encrypted_key1536) {
	SHA1_state		skyper = SHA1_INIT;
	u32				x192[48];
	u32				n = 0, i;

	big	x = mirvar(0);
	big	y = mirvar(0);
	big	m = mirvar(0);
	
    // expand 192bit (0x18h - 24 byte) to 0xC0
    // 0x30 = 48
    // expand 0x30h * 4
    // or 0x18h * 8
    // via 8 multiply reties .. hm or 4?
	
	for (i = 0; i < 8; i++) memcpy (x192+i*6, rand192, 24);

	show_memory(&x192, 192, "BUF_BEF_RSA_FOR_AES:");

	x192[0] &= 0xFFFFFF00;
	x192[0] |= 1;

	
	// Hashing it into 256-bit AES key
	SHA1_update (&skyper, &n, 4);
	SHA1_update (&skyper, x192, 192);
	SHA1_end (&skyper);
	memcpy (key256, skyper.hash, 20);
	n = 0x01000000;
	SHA1_init (&skyper);
	SHA1_update (&skyper, &n, 4);
	SHA1_update (&skyper, x192, 192);
	SHA1_end (&skyper);
	memcpy (key256+5, skyper.hash, 12);
	

	// Reversing byte order and RSA encrypting it for the server
	x->len = 48; for (i = 0; i < 48; i++) x->w[i] = _bswap32(x192[47-i]);
	m->len = 48; memcpy (m->w, Skype_Login_RSA_Key, 48*4);

	show_memory(x->w, 192, "BUF_BEF_RSA:");

	power(x, 0x10001, m, y);

	for (i = 0; i < 48; i++) encrypted_key1536[i] = _bswap32(y->w[47-i]);

	show_memory(encrypted_key1536, 192, "Produced_key1536_for_login1_pkt:");
	show_memory(key256, 0x20, "AES_KEY:");

	mirkill(x);
    mirkill(y); 
	mirkill(m); 

	return 0;
}


void AES_CTR (const u32 *key, u8 *pkt, const u32 bytes, const u32 IV)
{
	u32		blk[8] = {IV, IV, 0, 0}, ks[60], i, j;
	
	aes_256_setkey (key, ks);
	for (j = 0; j+16 < bytes; j += 16)
	{
		aes_256_encrypt (blk, blk+4, ks);
		dword(pkt,j+ 0) ^= _bswap32(blk[4]);
		dword(pkt,j+ 4) ^= _bswap32(blk[5]);
		dword(pkt,j+ 8) ^= _bswap32(blk[6]);
		dword(pkt,j+12) ^= _bswap32(blk[7]);
		blk[3]++;
	}
	if (j < bytes)
	{
		aes_256_encrypt (blk, blk+4, ks);
		for (i = 0; j < bytes; j++, i++) pkt[j] ^= ((u8 *)(blk+4))[i^3];
	}
}



// Returns 0 if communication error, otherwise the number of bytes returned in 'credentials'.

u32 SkypePrepareLoginPackets(u32 *public_key, char *login1, char *login2, u32 *n1, u32 *n2, u32 *key256) {
	u32					i, n, rand192[6], encrypted_key1536[48], hostid1[4], hostid2[5];
	u8					*p;
    int                 aesbuf_len;

	u8 aesbuf[0x1000] =
"\x17\x03\x01\x01\x17"
;

	// Generating 192-bit session key, should be random
	for (i = 0; i < 6; i++) srand32(), rand192[i] = rand32();

	Produce_Session_Key (rand192, key256, encrypted_key1536);


	// Faking HostIDs from public_key, this is NOT how Skype does it
	SHA1_hash (public_key, 128, hostid2);	// a = public_key; b = rand192?; c = sha1(ProductId); d = sha1(HDD0 ID); e = sha1(C Volume SN);
	hostid2[3] ^= hostid2[0]; hostid2[0] = public_key[0];	// matching Skype
	hostid2[2] ^= hostid2[1]; hostid2[1] = rand192[0];		// matching Skype
	MD5_hash (hostid2, 20, hostid1);	// only the first 64 bits of it are needed actually = sha1(c,d,e)
	hostid1[0] ^= hostid1[3];
	hostid1[1] ^= hostid1[2];


	// Forming Packet 1
	p  = login1;
	p += attach (p, "\x16\x03\x01\x00\xEB\x42\xCD\xEF\xE7\x40\xD7\x2F\x1D\xC0\xC6\x88\x80\xDF\xB7\x75\x37\x18\x69\x62\xB4\xEE\x3E", 27);
	p += attach (p, encrypted_key1536, 48*4);
	p += attach (p, "\x7D\x8A\xF3\x08\xD9\x36\xAF\x94\xF5\xA2\x2B\xE0\xE9\x06\x3F\xE4\x05\x72\xBB\x30\xE1", 21);
	*n1 = (u32) ((u32)p-(u32)login1);

	show_memory(login1, *n1, "Before RC4 encrypt");
	RC4_crypt (login1, *n1, &rc4_send, 0);
	show_memory(login1, *n1, "After RC4 encrypt");



	// Forming Packet 2
    aesbuf_len = encode41_loginpkt(aesbuf+5, 0x1000-5);
	memcpy(login2, aesbuf, aesbuf_len+5);
	n = aesbuf_len; 

	main_unpack_all(login2+5, n);

	show_memory(login2+5, n, "Before AES");
	AES_CTR (key256, login2+5, n, 0);
	show_memory(login2+5, n, "after AES");

	dword(login2+5,n) = crc8 (login2+5, n);

	// size fix
	*n2 = n+5+2;
	login2[3] = (u8) ((*n2-5)>>8);
	login2[4] = (u8) (*n2-5);

	show_memory(login2, *n2, "Before RC4 encrypt");
	RC4_crypt (login2, *n2, &rc4_send, 0);
	show_memory(login2, *n2, "After RC4 encrypt");


	return 0;
}


u32 do_login_process (char *username, char *password, u32 *public_key, u8 *credentials) {
	u8				b[1024];
	u8				login1[1024], login2[1024];
	u32	key256[8];
	u32	n1, n2;
	u32 n;


    strcpy(LOCAL_NAME, username);
    MD5_Skype_Password(username, password, LOCAL_AUTH_BUF);

    SkypePrepareLoginPackets(public_key, login1, login2, &n1, &n2, key256);

	if (send (sock, login1, n1, 0) != n1) return 0;	// WTF?
	if (send (sock, login2, n2, 0) != n2) return 0;	// WTF?
	printf("Send 2 formed pkts OK\n");

	n = recv (sock, b, sizeof(b), 0) - 7;
	printf("Received data2 OK\n");
	printf("Len: %d\n", n);
	show_memory(b, n+7, "recv data:");

	show_memory(b, n+7, "Before RC4 encrypt");
	RC4_crypt (b, n+7, &rc4_recv, 0);
	show_memory(b, n+7, "After RC4 encrypt");

	// some checks
	if (n > sizeof(b)-7) return 0;	// WTF?
	if (memcmp (b, "\x17\x03\x01", 3)) return 0;	// WTF?
	if (((u32)b[3]<<8)+b[4]-2 != n) return 0;	// WTF?
	if ((crc8 (b+5,n) & 0xFFFF) != word(b+5,n)) return 0;	// WTF?


	AES_CTR (key256, b+5, n, 1);
	
	show_memory(b+5, n, "Server AES Reply:");

	main_unpack_all(b+5, n);

	memcpy (credentials, b+5, n);


	return n;	// 14 == incorrect password; 285 == successful login, returned credentials; otherwise some other error
}



int do_skype_login (char *username, char *password) {
	u32			i;
	u8			credentials[1024];
	big			p, q, public_key;
    u8          public_key_bytes[0x81];


	// Generating 1024-bit RSA keypair
	gprime (16384);
	p = mirvar (0); p->len = 16; for (i = 0; i < 16; i++) srand32(), p->w[i] = rand32();
    p->w[15] |= 0x80000000; 
    nxprime (p, p);
	q = mirvar (0); q->len = 16; for (i = 0; i < 16; i++) srand32(), q->w[i] = rand32();
    q->w[15] |= 0x80000000; 
    nxprime (q, q);

	// Calculating public key
	public_key = mirvar (0); 
	multiply (p, q, public_key);

	big_to_bytes(0x80, public_key, public_key_bytes,TRUE);

	memcpy(PUBLIC_KEY, public_key_bytes, 0x80);

    show_memory(PUBLIC_KEY, 0x80, "Public key:");

	//i = do_login_process("themagicforyou", "adf123", public_key->w, credentials);
	i = do_login_process(username, password, public_key->w, credentials);

	printf("i: 0x%08X\n", i);
	printf("i: %d\n", i);

	// now check i = number of received bytes and the content of 'credentials'
	// save p and q as the secret key
	// save credentials containing the RSA-encrypted and signed public key
	if (i == 285) {
        //bytes_to_big(0x100,buf,m);
		dump_cred(username, p->w, q->w, credentials, i);
	};

	return i;
}
