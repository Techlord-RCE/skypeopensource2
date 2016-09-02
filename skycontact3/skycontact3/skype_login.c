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

#include "skype/skype_rc4.h"
#include "skype/skype_basics.h"

#include "crypto/md5.h"
#include "crypto/sha1.h"
#include "crypto/rijndael.h"

#include "miracl_lib/miracl.h"


// global data
extern RC4_context rc4_send;
extern RC4_context rc4_recv;

extern int sock;

u8 aes_key[0x20];

unsigned int blkseq;


u8 LOCAL_NAME[0x100];
u8 LOCAL_AUTH_BUF[0x11];

u8 CLIENT_VERSION[0x100] = "0/6.16.0.10//";
//u8 CLIENT_VERSION[0x100]="0/5.5.0.124//";


char REMOTE_INDEXBUF[0x1000];
int REMOTE_INDEXBUF_LEN;

int flag_auth_fail = 0;
int flag_blob_04_35 = 0;
int flag_contacts_remain = 0;
int flag_commands_remain = 0;



u32				Skype_Login_RSA_Key[48] =
{
	0xBA29700B,0xB57250D7,0x55AAA3A4,0x335A48C9,0xF51DA404,0xCA8F4446,0x31CC2BC4,0xA6C8F1FF,
	0xA2007ACF,0xC8E25638,0xDD2D8732,0xAFD95B80,0xC873E95C,0x3D4C2625,0x1A3EAB16,0x99492AA6,
	0x97CED2E1,0xB7138523,0x6C0375EE,0x8202C61C,0x66B23E1F,0x093AC6EE,0x385EF5F4,0xAD0A804F,
	0x78627651,0xAC550B39,0x0E7A9EAF,0xA4C35289,0xEDB35DCB,0x40468CF0,0xCD9914E5,0x140CA82C,
	0xC88B3CAE,0x96350989,0x692015E7,0x9484B597,0xC0E5ABE0,0x7752A248,0xC72E53EF,0x5D74A14C,
	0xEC983AAB,0xEC87304A,0x6C1AF0FB,0x532A72DF,0x310B0B21,0x1EF1CA5E,0x2F4F5FC8,0xA8F22361
};


u32 encode32 (u8 * const to, const u32 * const from, const u32 words) {
	u32		n = 0, i, a;

	for (i = 0; i < words; i++) { for (a = from[i]; a > 0x7F; a >>= 7, n++) to[n] = (u8) a | 0x80; to[n++] = (u8) a; }
	return n;
}

static u32 decode32 (u32 * const to, const u8 * const from, const u32 bytes) {
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

// rand192 -- input buf
// key256 -- outpub buf
// encrypted_key1536 -- outpub buf
int Produce_Session_Key (const u32 *rand192, u32 *key256, u32 *encrypted_key1536) {
	SHA1_state		skyper = SHA1_INIT;
	u32				x192[48];
	u32				n = 0, i;


	big	x = mirvar(0);
	big	m = mirvar(0);
	big	y = mirvar(0);
	
	for (i = 0; i < 8; i++) memcpy (x192+i*6, rand192, 24);

	show_memory(&x192, 192, "BUF_BEF_RSA_FOR_AES:");

	x192[0] &= 0xFFFFFF00;
	x192[0] |= 1;
	
	// for aes_key
	// need rand192 hash with some special values 

	// Hashing it into 256-bit AES key
	n = 0x00;
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
	
	// aes key done.

	// for encrypted_key1536
	// need rand192 multiply on Skype_Login_RSA_Key

	// Reversing byte order and RSA encrypting it for the server
	x->len = 48; for (i = 0; i < 48; i++) x->w[i] = _bswap32(x192[47-i]);
	m->len = 48; memcpy (m->w, Skype_Login_RSA_Key, 48*4);

	show_memory(x->w, 192, "BUF_BEF_RSA:");

	power (x, 0x10001, m, y);

	for (i = 0; i < 48; i++) encrypted_key1536[i] = _bswap32(y->w[47-i]);

	// encrypted_key1536 done

	show_memory(encrypted_key1536, 192, "Produced_key_for_login1_pkt:");
	show_memory(key256, 0x20, "AES_KEY:");

	mirkill(x);
	mirkill(m); 
    mirkill(y); 

	return 0;
}


u32 SkypePrepareLoginPacket(u32 *encrypted_key1536, char *login1, u32 *n1) {
	u32					hostid1[4], hostid2[5];
	u8					*p;


	/*
	// Faking HostIDs from public_key, this is NOT how Skype does it
	SHA1_hash (public_key, 128, hostid2);	// a = public_key; b = rand192?; c = sha1(ProductId); d = sha1(HDD0 ID); e = sha1(C Volume SN);
	hostid2[3] ^= hostid2[0]; hostid2[0] = public_key[0];	// matching Skype
	hostid2[2] ^= hostid2[1]; 
	hostid2[1] = rand192[0];		// matching Skype
	MD5_hash (hostid2, 20, hostid1);	// only the first 64 bits of it are needed actually = sha1(c,d,e)
	hostid1[0] ^= hostid1[3];
	hostid1[1] ^= hostid1[2];
	*/

	// Forming Packet 1
	p  = login1;
	p += attach (p, "\x16\x03\x01\x00\xEB\x42\xCD\xEF\xE7\x40\xD7\x2F\x1D\xC0\xC6\x88\x80\xDF\xB7\x75\x37\x18\x69\x62\xB4\xEE\x3E", 27);
	p += attach (p, encrypted_key1536, 48*4);
	p += attach (p, "\x7D\x8A\xF3\x08\xD9\x36\xAF\x94\xF5\xA2\x2B\xE0\xE9\x06\x3F\xE4\x05\x72\xBB\x30\xE1", 21);
	*n1 = (u32) ((u32)p-(u32)login1);

	show_memory(login1, *n1, "Before RC4 encrypt");
	RC4_crypt(login1, *n1, &rc4_send, 0);
	show_memory(login1, *n1, "After RC4 encrypt");

	return 0;
}


u32 SkypePrepareAESPacket2(char *login, u32 *nlen, u32 *key256) {
	u32					i, n;
	u8					*p;

	u8 buf1[0x1000];
	int buf1_len;
	u8 buf1header[0x10];
	int buf1header_len;

	u32 aes_len;
	u8 aesbuf[0x1000] =
"\x17\x03\x01\x00\x5F"
;

  	aes_len = encode41_auth2pkt(aesbuf+5, sizeof(aesbuf)-5);
	aes_len += 5;
	show_memory(aesbuf, aes_len, "auth2pkt");

	p = login;
	memcpy(login, aesbuf, aes_len);
	n = aes_len - 5;

	printf("\n\nPKT2\n\n");

	main_unpack_all(login+5, n);

    process_aes_noid(login+5, n, 1, 1);

	*nlen = n+5+2;
	login[3] = (u8) ((*nlen-5)>>8);
	login[4] = (u8) (*nlen-5);

	show_memory(login, *nlen, "Before RC4 encrypt");
	RC4_crypt (login, *nlen, &rc4_send, 0);
	show_memory(login, *nlen, "After RC4 encrypt");

	return 0;
};


u32 SkypePrepareAESPacket3(char *login, u32 *nlen, u32 *key256) {
	u32					i, n;
	u8					*p;

	u32 aes_len;
	u8 aesbuf[0x1000] =
"\x17\x03\x01\x00\x69"
;
    unsigned int sess_id, pkt_id;

    sess_id = 0x178C;
    pkt_id = 0x04;

  	aes_len = encode41_auth3pkt(aesbuf+5, sizeof(aesbuf)-5, sess_id, pkt_id);
	aes_len += 5;
	show_memory(aesbuf, aes_len, "auth3pkt");

	p = login;
	memcpy(login, aesbuf, aes_len);
	n = aes_len - 5;

	printf("\n\nPKT3\n\n");

	main_unpack_all(login+5, n);

    process_aes_noid(login+5, n, 1, 1);

	// size fix
	*nlen = n+5+2;
	login[3] = (u8) ((*nlen-5)>>8);
	login[4] = (u8) (*nlen-5);

	show_memory(login, *nlen, "Before RC4 encrypt");
	RC4_crypt (login, *nlen, &rc4_send, 0);
	show_memory(login, *nlen, "After RC4 encrypt");

	return 0;

};


// step2
u32 SkypePrepareAESPacket4(char *login, u32 *nlen, u32 *key256, 
            unsigned int sess_id, unsigned int pkt_id, unsigned int sync_idx){
	u32					i, n;
	u8					*p;

	u32 aes_len;
	u8 aesbuf[0x1000] =
"\x17\x03\x01\x00\x70"
;

  	aes_len = encode41_auth4pkt(aesbuf+5, sizeof(aesbuf)-5, sess_id, pkt_id, sync_idx);
	aes_len += 5;
	show_memory(aesbuf, aes_len, "auth4pkt");

	p = login;
	memcpy(login, aesbuf, aes_len);
	n = aes_len - 5;

	printf("\n\nPKT4\n\n");

	main_unpack_all(login+5, n);

    process_aes_noid(login+5, n, 1, 1);

	// size2 fix
	*nlen = n+5+2;
	login[3] = (u8) ((*nlen-5)>>8);
	login[4] = (u8) (*nlen-5);

	show_memory(login, *nlen, "Before RC4 encrypt");
	RC4_crypt (login, *nlen, &rc4_send, 0);
	show_memory(login, *nlen, "After RC4 encrypt");

	return 0;

};


u32 SkypePrepareAESPacket7(char *login, u32 *nlen, u32 *key256,
            unsigned int sess_id, unsigned int pkt_id, unsigned int sync_idx){
	u32					i, n;
	u8					*p;

	u32 aes_len;
	u8 aesbuf[0x1000] =
"\x17\x03\x01\x00\x62"
;

  	aes_len = encode41_auth7pkt(aesbuf+5, sizeof(aesbuf)-5, sess_id, pkt_id, sync_idx);
	aes_len += 5;
	show_memory(aesbuf, aes_len, "auth7pkt");

	p = login;
	memcpy(login, aesbuf, aes_len);
	n = aes_len - 5;

	printf("\n\nPKT7\n\n");

	main_unpack_all(login+5, n);

    process_aes_noid(login+5, n, 1, 1);

	// size fix
	*nlen = n+5+2;
	login[3] = (u8) ((*nlen-5)>>8);
	login[4] = (u8) (*nlen-5);

	show_memory(login, *nlen, "Before RC4 encrypt");
	RC4_crypt (login, *nlen, &rc4_send, 0);
	show_memory(login, *nlen, "After RC4 encrypt");

	return 0;

};


u32 do_skype_getcontacts (char *username, char *password) {
	u8				b[0x20000];
	//u8				b[0x100000]; // 1mb buf for recv
	//u8				*b;
	u8				login1[1024], login2[1024], login3[1024];
	u8				login4[1024], login5[1024], login6[1024];
	u8				login7[1024], login8[1024], login9[1024];
	u8				login10[1024];
	u8				login11[1024];
    u8 hash128[0x11];
	u32	n1, n2, n3;
	u32	n4, n5, n6;
	u32 n7, n8, n9, n10, n11;
	int n;
	int j;
	int ext_flag;
	int i;
    unsigned int sess_id, pkt_id, sync_idx;
    int reqnum;
	int curr_size;
	int n_add;

	u32	key256[8];
	u32	rand192[6], encrypted_key1536[48];

	// 1mb buf for recv
	//b = (u8 *)malloc(0x100000); 
	//printf("b buf 0x%08X\n", b);

    blkseq = 0;

    strcpy(LOCAL_NAME, username);
    MD5_Skype_Password(username, password, LOCAL_AUTH_BUF);


	// Generating 192-bit session key, should be random
	for (i = 0; i < 6; i++) srand32(), rand192[i] = rand32();

	Produce_Session_Key (rand192, key256, encrypted_key1536);
	memcpy(aes_key, key256, 0x20);

	SkypePrepareLoginPacket(encrypted_key1536, login1, &n1);

	SkypePrepareAESPacket2(login2, &n2, key256);
	SkypePrepareAESPacket3(login3, &n3, key256);

	if (send (sock, login1, n1, 0) != n1) return 0;	// WTF?
	if (send (sock, login2, n2, 0) != n2) return 0;	// WTF?
	if (send (sock, login3, n3, 0) != n3) return 0;	// WTF?

	printf("Send 3 formed pkts OK\n");

    j = 0;
	ext_flag = 1;
	while(ext_flag) {

		n = recv (sock, b, sizeof(b), 0);

		// some checks
		//if (memcmp (b, "\x17\x03\x01", 3)) return 0;	// WTF?
		//if (((u32)b[3]<<8)+b[4]-2 != n) return 0;	// WTF?
		//if ((crc8 (b+5,n) & 0xFFFF) != word(b+5,n)) return 0;	// WTF?

		if (n<0) {
			printf("recv fail\n");
			return -1;
		};

		printf("\n\n\nReceived data %d pkt OK\n", j);
		printf("Len: %d\n\n", n);

		show_memory(b, n, "Before RC4 encrypt");
		RC4_crypt (b, n, &rc4_recv, 0);
		show_memory(b, n, "After RC4 encrypt");

		process_recv_data(b, n);

		if (flag_blob_04_35) {
			ext_flag = 0;
		};
		if (flag_auth_fail) {
            // username or password incorrect
			printf("Authentication failed.\n");
			return 0;
		};

        j++;
	};


    /*
    // for echo123 add, not like skype do it
    //reqnum = REMOTE_INDEXBUF_LEN / 4;
    */

    reqnum = (REMOTE_INDEXBUF_LEN / 4) - 1;
    printf("num of requests needed = %d\n", reqnum);
    for(i=0;i<reqnum;i++) {
        memcpy(&sync_idx, REMOTE_INDEXBUF+(i*4),4);
    	sync_idx = _bswap32(sync_idx);
        printf("synx_id = 0x%08X\n", sync_idx);

        sess_id = 0x1788;
        pkt_id = 0x07 + i;
        //sync_idx = 0x69235765;
       	SkypePrepareAESPacket4(login4, &n4, key256, sess_id, pkt_id, sync_idx);

       	if (send (sock, login4, n4, 0) != n4) return 0;	// WTF?
    };

	printf("Send step2 5 formed pkts OK\n");

    flag_contacts_remain = reqnum;

	j = 0;
	ext_flag = 1;
	while(ext_flag) {
		n = recv (sock, b, sizeof(b), 0);
		if (n<0) {
			printf("recv fail\n");
			return -1;
		};

        n_add = n;
		while (n_add == 1024) {
			printf("do additional recv\n");
			curr_size = n;
			n_add = recv (sock, b+curr_size, sizeof(b), 0);
			n = n + n_add;
		};

		printf("\n\n\nReceived data %d pkt OK\n", j);
		printf("Len: %d\n\n", n);

		show_memory(b, n, "Before RC4 encrypt");
		RC4_crypt (b, n, &rc4_recv, 0);
		show_memory(b, n, "After RC4 encrypt");

		process_recv_data(b, n);

		if (flag_contacts_remain == 0) {
			ext_flag = 0;
		};

		j++;
	};

    sess_id = 0x1780;
    //pkt_id = 0x0C;
    pkt_id = 0x07 + reqnum;
    sync_idx = 0x00000000;
	SkypePrepareAESPacket7(login9, &n9, key256, sess_id, pkt_id, sync_idx);

    sess_id = 0x1781;
    //pkt_id = 0x0E;
    pkt_id += 2;
    sync_idx = 0x00000000;
	SkypePrepareAESPacket7(login10, &n10, key256, sess_id, pkt_id, sync_idx);

	if (send (sock, login9, n9, 0) != n9) return 0;	// WTF?
	if (send (sock, login10, n10, 0) != n10) return 0;	// WTF?

	printf("Send step3 2 formed pkts OK\n");

    flag_commands_remain = 2;
	j = 0;
	ext_flag = 1;
	while(ext_flag) {
		n = recv (sock, b, sizeof(b), 0);
		if (n<0) {
			printf("recv fail\n");
			return -1;
		};

		printf("\n\n\nReceived data %d pkt OK\n", j);
		printf("Len: %d\n\n", n);

		show_memory(b, n, "Before RC4 encrypt");
		RC4_crypt (b, n, &rc4_recv, 0);
		show_memory(b, n, "After RC4 encrypt");

		process_recv_data(b, n);

		if (flag_commands_remain == 0) {
			ext_flag = 0;
		};
        if (j > 10) {
            printf("Recv loop, emergency return...\n");
            return -1;
        };

		j++;
	};

    sess_id = 0x1780;
    //pkt_id = 0x12;
    pkt_id += 4;
    sync_idx = 0x3B9ACA28;
	SkypePrepareAESPacket7(login11, &n11, key256, sess_id, pkt_id, sync_idx);

	if (send (sock, login11, n11, 0) != n11) return 0;	// WTF?

	printf("Send step4 1 formed pkt OK\n");

    flag_commands_remain = 1;
	j = 0;
	ext_flag = 1;
	while(ext_flag) {
		n = recv (sock, b, sizeof(b), 0);
		if (n<0) {
			printf("recv fail\n");
			return -1;
		};

		printf("\n\n\nReceived data %d pkt OK\n", j);
		printf("Len: %d\n\n", n);

		show_memory(b, n, "Before RC4 encrypt");
		RC4_crypt (b, n, &rc4_recv, 0);
		show_memory(b, n, "After RC4 encrypt");

		process_recv_data(b, n);

		if (flag_commands_remain == 0) {
			//ext_flag = 0;
			ext_flag = 0;
		};
        if (j > 10) {
            printf("Recv loop, emergency return...\n");
            return -1;
        };

		j++;
	};

	printf("All OK! Sync session done!\n");

	return 1;
}
