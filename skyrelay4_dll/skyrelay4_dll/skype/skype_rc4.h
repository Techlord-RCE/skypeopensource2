/*\
|*|
|*| Skype RC4 v1 by Sean O'Neil.
|*| Copyright (c) 2004-2009 by VEST Corporation.
|*| All rights reserved. Strictly Confidential!
|*|
\*/

#ifndef _skype_rc4_
#define _skype_rc4_

#include <stdio.h>
#include <stdlib.h>

#include "skype_basics.h"

typedef struct _RC4_context
{
	u32						from_IP, to_IP, from_port, to_port, seq;
	u8						i, j, s[256];
	struct _RC4_context		*next;
} RC4_context;

void RC4_crypt (u8 * buffer, u32 bytes, RC4_context * const rc4, const u32 test); // RC4 encrypt/decrypt (test=1 leaves rc4 context unaltered)
void Skype_RC4_Expand_IV (const u32 iv, const void *iv2, RC4_context * const rc4, const u32 flags, const u32 iv2_bytes);	// Main RC4 IV expansion function, matching Skype parameters

extern u32 __fastcall Expand_IVa (u32 * const key, u32 n);	// Top-layer RC4 IV expansion function
extern u32 __fastcall Expand_IVb (u32 * const key, u32 n);	// Top-layer RC4 IV expansion function

typedef void __fastcall skype_rc4_macro (u32 * const key, u32 n);

extern u32 __fastcall Expand_IV1 (u32 * const key, u32 n);
extern u32 __fastcall Expand_IV2 (u32 * const key, u32 n);
extern u32 __fastcall Expand_IV3 (u32 * const key, u32 n);
extern u32 __fastcall Expand_IV4 (u32 * const key, u32 n);
extern u32 __fastcall Expand_IV5 (u32 * const key, u32 n);
extern u32 __fastcall Expand_IV6 (u32 * const key, u32 n);
extern u32 __fastcall Expand_IV7 (u32 * const key, u32 n);
extern u32 __fastcall Expand_IV8 (u32 * const key, u32 n);
extern u32 __fastcall Expand_IV9 (u32 * const key, u32 n);
extern u32 __fastcall Expand_IV10 (u32 * const key, u32 n);
extern u32 __fastcall Expand_IV11 (u32 * const key, u32 n);
extern u32 __fastcall Expand_IV12 (u32 * const key, u32 n);
extern u32 __fastcall Expand_IV13 (u32 * const key, u32 n);
extern u32 __fastcall Expand_IV14 (u32 * const key, u32 n);
extern u32 __fastcall Expand_IV15 (u32 * const key, u32 n);
extern u32 __fastcall Expand_IV16 (u32 * const key, u32 n);
extern u32 __fastcall Expand_IV17 (u32 * const key, u32 n);
extern u32 __fastcall Expand_IV18 (u32 * const key, u32 n);
extern u32 __fastcall Expand_IV19 (u32 * const key, u32 n);
extern u32 __fastcall Expand_IV20 (u32 * const key, u32 n);
extern u32 __fastcall Expand_IV21 (u32 * const key, u32 n);
extern u32 __fastcall Expand_IV22 (u32 * const key, u32 n);
extern u32 __fastcall Expand_IV23 (u32 * const key, u32 n);
extern u32 __fastcall Expand_IV24 (u32 * const key, u32 n);

#define	Recurse_IV1(key,n)	{if (Expand_IV1 (key, n)) 1;}
#define	Recurse_IV2(key,n)	{if (Expand_IV2 (key, n)) 1;}
#define	Recurse_IV3(key,n)	{if (Expand_IV3 (key, n)) 1;}
#define	Recurse_IV4(key,n)	{if (Expand_IV4 (key, n)) 1;}
#define	Recurse_IV5(key,n)	{if (Expand_IV5 (key, n)) 1;}
#define	Recurse_IV6(key,n)	{if (Expand_IV6 (key, n)) 1;}
#define	Recurse_IV7(key,n)	{if (Expand_IV7 (key, n)) 1;}
#define	Recurse_IV8(key,n)	{if (Expand_IV8 (key, n)) 1;}
#define	Recurse_IV9(key,n)	{if (Expand_IV9 (key, n)) 1;}
#define	Recurse_IV10(key,n)	{if (Expand_IV10 (key, n)) 1;}
#define	Recurse_IV11(key,n)	{if (Expand_IV11 (key, n)) 1;}
#define	Recurse_IV12(key,n)	{if (Expand_IV12 (key, n)) 1;}
#define	Recurse_IV13(key,n)	{if (Expand_IV13 (key, n)) 1;}
#define	Recurse_IV14(key,n)	{if (Expand_IV14 (key, n)) 1;}
#define	Recurse_IV15(key,n)	{if (Expand_IV15 (key, n)) 1;}
#define	Recurse_IV16(key,n)	{if (Expand_IV16 (key, n)) 1;}
#define	Recurse_IV17(key,n)	{if (Expand_IV17 (key, n)) 1;}
#define	Recurse_IV18(key,n)	{if (Expand_IV18 (key, n)) 1;}
#define	Recurse_IV19(key,n)	{if (Expand_IV19 (key, n)) 1;}
#define	Recurse_IV20(key,n)	{if (Expand_IV20 (key, n)) 1;}
#define	Recurse_IV21(key,n)	{if (Expand_IV21 (key, n)) 1;}
#define	Recurse_IV22(key,n)	{if (Expand_IV22 (key, n)) 1;}
#define	Recurse_IV23(key,n)	{if (Expand_IV23 (key, n)) 1;}
#define	Recurse_IV24(key,n)	{if (Expand_IV24 (key, n)) 1;}

#endif
