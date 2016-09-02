// dh-384 bit functions


#include "skype/skype_rc4.h"


// global data
extern RC4_context rc4_send;
extern RC4_context rc4_recv;



void Skypelogin_RC4_init (char *rc4_seed, RC4_context * rc4) {
	memcpy(rc4->s, rc4_seed, 0x100);	
	rc4->i = 0;
	rc4->j = 0;
}



int extconn_rc4_crypto_genkey(char *inbuf) {
	unsigned int i, ecx;
	unsigned long edx;
	char result[0x104];

	show_memory(inbuf, 0x30, "rc4_seed input:");

	rc4_key_generate(result, inbuf, 0x30);
	show_memory(result, 0x100, "rc4_seed rc4_send result:");
	Skypelogin_RC4_init (result, &rc4_send);

	inbuf[0]=inbuf[0] + 1;
	rc4_key_generate(result, inbuf, 0x30);
	show_memory(result, 0x100, "rc4_seed rc4_recv result:");
	Skypelogin_RC4_init (result, &rc4_recv);

	return 0;

};




// from defs.h of hexrays
#define _BYTE  char
#define _WORD  short
#define _DWORD long

// arg0:inbuf, arg4:inlen, ecx = rc4 keybuf:100h
int rc4_key_generate(int buf, int a_key, unsigned int a_len)
{
  int ret; // eax@1
  unsigned int v4; // edx@1
  unsigned int v5; // edi@3
  unsigned int v6; // esi@3
  int v7; // edx@4

  ret = 0;
  *(_WORD *)(buf + 256) = 0;
  v4 = 0;
  do
  {
    *(_BYTE *)(v4 + buf) = v4;
    ++v4;
  }
  while ( v4 < 0x100 );


  v6 = 0;
  v5 = 0;
  do
  {
    v7 = *(_BYTE *)(v5 + buf);
    ret = (v7 + *(_BYTE *)(v6++ + a_key) + ret) & 0xFF;
    *(_BYTE *)(v5 + buf) = *(_BYTE *)(ret + buf);
    *(_BYTE *)(ret + buf) = v7;
    if ( v6 >= a_len )
      v6 = 0;
    ++v5;
  }
  while ( v5 < 0x100 );

  return ret;
};

