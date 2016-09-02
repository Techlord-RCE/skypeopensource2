/*\
|*|
|*| Skype Protocol v0.107 by Sean O'Neil.
|*| Copyright (c) 2009 by VEST Corporation.
|*| All rights reserved. Strictly Confidential!
|*|
|*| Date: 24.11.2009
|*|
\*/

#ifndef _skype_basics_h_
#define _skype_basics_h_


#ifndef u8
    typedef unsigned char		u8;
#endif
#ifndef u16
    typedef unsigned short		u16;
#endif
#ifndef u32
    typedef unsigned long		u32;
#endif
#ifndef u64
    typedef unsigned long long	u64;
#endif


#include <stdlib.h>
#include <string.h>

#ifdef __GNUC__
	#define __FAVOR_BSD
	#include <stdint.h>
	#include <unistd.h>
	#include <sys/signal.h>
	#include <sys/socket.h>
	#include <sys/time.h>
	#include <netinet/in.h>
	#include <netinet/in_systm.h>
	#include <netinet/ip.h>
	#include <netinet/tcp.h>
	#include <netinet/udp.h>
	#include <arpa/inet.h>
	typedef int				SOCKET;
	#ifndef __fastcall
		#define __fastcall	__attribute__((fastcall))
	#endif
	#define __forceinline	__inline__
	#define					rotl32(x,r) (((x)<<((r)&31))|((x)>>((0-(r))&31)))
	#define					rotr32(x,r) (((x)>>((r)&31))|((x)<<((0-(r))&31)))
	#define					rotl64(x,r) (((x)<<((r)&63))|((x)>>((0-(r))&63)))
	#define					rotr64(x,r) (((x)>>((r)&63))|((x)<<((0-(r))&63)))
	#pragma GCC				option(popcnt)
	#define popcnt32(x)		__builtin_popcount(x)
	static __inline__ u32	_bswap32 (u32 x) { __asm__ ("bswapl %0" : "=r" (x) : "0" (x)); return x; }
	static __inline__ u64	rdtsc(void) {register u64 x; __asm__ volatile (".byte 0x0F, 0x31" : "=A" (x)); return x; }
	#define LL				"ll"
	#ifndef __min
		static __inline__ u32 __min (u32 a, u32 b) { return a<b?a:b; }
	#endif
#else
	#include <intrin.h>
	#include <time.h>
	#include <winsock.h>
	#define close(x)		closesocket(x)
	#define ssize_t			size_t
	#define socklen_t		u32
	#define __inline__		__forceinline
	#define					rotl32(x,r) _lrotl(x,r)
	#define					rotr32(x,r) _lrotr(x,r)
	#define					rotl64(x,r) _rotl64(x,r)
	#define					rotr64(x,r) _rotr64(x,r)
	static __inline__ u32	popcnt32 (u32 x) {register u32 n=0;while(x)n++,x&=x-1;return n;}
	static __inline__ u32	_bswap32 (u32 x) {__asm{mov eax,x}__asm{bswap eax}}
	#define rdtsc()			__rdtsc()
	#define LL				"I64"
#endif

#if defined(__BYTE_ORDER)&&(__BYTE_ORDER==4321)||defined(BYTE_ORDER)&&(BYTE_ORDER==4321)||defined(sun)||defined(__sun)||defined(sparc)||defined(__sparc)||defined(__ppc__)
	#define SKYPE_4321_BYTE_ORDER
#elif defined(__BYTE_ORDER)&&(__BYTE_ORDER==1234)||defined(BYTE_ORDER)&&(BYTE_ORDER==1234)||defined(i386)||defined(__i386__)||defined(__amd64__)||defined(__x86_64__)||defined(__vax__)||defined(__alpha)||defined(__ultrix)||defined(_M_IX86)||defined(_M_IA64)||defined(_M_X64)||defined(_M_ALPHA)
	#define SKYPE_1234_BYTE_ORDER
#else
	#error Unknown endianness! Please define or disable this error and check at runtime.
#endif

#ifdef SKYPE_4321_BYTE_ORDER
	#define ord2(x)			((x)^1)
	#define make_MSF_32(x,n)
	static __inline__ void	make_LSF_32 (u32 *x, u32 n) { register u32 i; for (; n; x++, n--) { i = *x; *x = _bswap32 (i); } }
#elif defined (SKYPE_1234_BYTE_ORDER)
	#define ord2(x)			(x)
	#define make_LSF_32(x,n)
	static __inline__ void	make_MSF_32 (u32 *x, u32 n) { register u32 i; for (; n; x++, n--) { i = *x; *x = _bswap32 (i); } }
#else
	#error Sorry!
#endif



#define byte(x,n)			(*(u8*)(((u8*)(x))+(n)))
#define word(x,n)			(*(u16*)(((u8*)(x))+(n)))
#define dword(x,n)			(*(u32*)(((u8*)(x))+(n)))
#define qword(x,n)			(*(u64*)(((u8*)(x))+(n)))

static __inline__ u16 _bswap16 (u16 x) {return (u16)(((x&0xFF)<<8)+((x>>8)&0xFF));}
#define CRC1(s,g)			(s=((s)&1)?((s)>>1)^(g):((s)>>1))
#define CRC8(s,g)			for(j=0;j<8;j++)CRC1(s,g);
#define CRC32(s,g)			for(j=0;j<32;j++)CRC1(s,g);

static u32					_rnd32a, _rnd32b;	// a very small fast PRNG to randomise in/out processing and possibly other operations
#define hash32(a,b)			((a)^=rotr32((b)^0x7BED1AFD,9)*0xFEE1BEA7,(b)^=rotr32((a)^0xFEA4BAD5,9)*0xDAD5FED3)
#define rnd32()				hash32(_rnd32a,_rnd32b)

static u64					_rand64[2] = { 0xE4FDC25B98A63017ULL, 0x5EA93C21F7604D8BULL };	// a normal size [P]RNG (slower)
#define rand64()			(_rand64[1] ^= (rotl64 (_rand64[0], 17) ^ 0x5AC734E821DF60B9ULL), _rand64[0] += rotl64 (_rand64[1] * 0x2C0DE96B357481AFULL ^ 0xD8725E3901A4F6CBULL, 13))
#define srand64()			(_rand64[0] ^= _rand64[1] += rdtsc ())
#define rand32()			((u32) rand64())
#define srand32()			((u32) srand64())
#define zrand32(d,l)		(MD5_hash(d,l,_rand64))

static u32 crc8  (const u8  *x, u32 n){u32 j,z=-1;for(;n;n--){z^=*x++;CRC8 (z,0xEDB88320);}return z;}
static u32 crc32 (const u32 *x, u32 n){u32 j,z=-1;for(;n;n--){z^=*x++;CRC32(z,0xEDB88320);}return z;}

#ifndef min
	#define min(a,b)		(((a)<(b))?(a):(b))
#endif
#ifndef max
	#define max(a,b)		(((a)>(b))?(a):(b))
#endif

#define skrand(x)			((x)*0x00010DCD+0x00004271)	// *10DCD=+4271=
#define skback(x)			((x)*0xA5E2A705+0x57E4FCCB)	// *A5E2A705=+57E4FCCB=

static u8					skype_ssl_client_hello[56] =
{
	0x80,0x46,				// 0x80 | data length
	0x01,0x03,0x01,			// TLS v1 client hello
	0x00,0x2d,				// 45/3 = 15 cipher specs
	0x00,0x00,				//  0-byte session ID
	0x00,0x10,				// 16-byte challenge
	0x00,0x00,0x05,			// TLS_RSA_WITH_RC4_128_SHA
	0x00,0x00,0x04,			// TLS_RSA_WITH_RC4_128_MD5
	0x00,0x00,0x0a,			// TLS_RSA_WITH_3DES_EDE_CBC_SHA
	0x00,0x00,0x09,			// TLS_RSA_WITH_DES_CBC_SHA
	0x00,0x00,0x64,			// TLS_RSA_EXPORT1024_WITH_RC4_56_SHA
	0x00,0x00,0x62,			// TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA
	0x00,0x00,0x08,			// TLS_RSA_EXPORT_WITH_DES40_CBC_SHA
	0x00,0x00,0x03,			// TLS_RSA_EXPORT_WITH_RC4_40_MD5
	0x00,0x00,0x06,			// TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5
	0x01,0x00,0x80,			// SSL2_RC4_128_WITH_MD5
	0x07,0x00,0xc0,			// SSL2_DES_192_EDE3_CBC_WITH_MD5
	0x03,0x00,0x80,			// SSL2_RC2_CBC_128_CBC_WITH_MD5
	0x06,0x00,0x40,			// SSL2_DES_64_CBC_WITH_MD5
	0x02,0x00,0x80,			// SSL2_RC4_128_EXPORT40_WITH_MD5
	0x04,0x00,0x80			// SSL2_RC2_CBC_128_CBC_WITH_MD5
};

static u8					skype_ssl_server_hello[79] =
{
	0x16,0x03,0x01,0x00,0x4A,0x02,0x00,0x00,0x46,0x03,0x01,0x40,0x1B,0xE4,0x86,0x02,
	0xAD,0xE0,0x29,0xE1,0x77,0x74,0xE5,0x44,0xB9,0xC9,0x9C,0xB4,0x31,0x31,0x5E,0x02,
	0xDD,0x77,0x9D,0x15,0x4A,0x96,0x09,0xBA,0x5D,0xA8,0x70,0x20,0x1C,0xA0,0xE4,0xF6,
	0x4C,0x63,0x51,0xAE,0x2F,0x8E,0x4E,0xE1,0xE6,0x76,0x6A,0x0A,0x88,0xD5,0xD8,0xC5,
	0x5C,0xAE,0x98,0xC5,0xE4,0x81,0xF2,0x2A,0x69,0xBF,0x90,0x58,0x00,0x05,0x00
};

static u32					skype_384_bit_dh_modulus[12] =
{
	0xFFFFFFFF,0xFFFFFFFF,0x3B13B202,0x020BBEA6,0x8A67CC74,0x29024E08,0x80DC1CD1,0xC4C6628B,
	0x2168C234,0xC90FDAA2,0xFFFFFFFF,0xFFFFFFFF
};

static u32					skype_login_rsa_key[48] =
{
	0xBA29700B,0xB57250D7,0x55AAA3A4,0x335A48C9,0xF51DA404,0xCA8F4446,0x31CC2BC4,0xA6C8F1FF,
	0xA2007ACF,0xC8E25638,0xDD2D8732,0xAFD95B80,0xC873E95C,0x3D4C2625,0x1A3EAB16,0x99492AA6,
	0x97CED2E1,0xB7138523,0x6C0375EE,0x8202C61C,0x66B23E1F,0x093AC6EE,0x385EF5F4,0xAD0A804F,
	0x78627651,0xAC550B39,0x0E7A9EAF,0xA4C35289,0xEDB35DCB,0x40468CF0,0xCD9914E5,0x140CA82C,
	0xC88B3CAE,0x96350989,0x692015E7,0x9484B597,0xC0E5ABE0,0x7752A248,0xC72E53EF,0x5D74A14C,
	0xEC983AAB,0xEC87304A,0x6C1AF0FB,0x532A72DF,0x310B0B21,0x1EF1CA5E,0x2F4F5FC8,0xA8F22361
};

static u32					skype_credentials_key[65] =
{
	0x2EDC2855,0xBC37FE33,0x0258748D,0xCA8251B5,0x1D977915,0xCE6875A7,0x6AB8CA45,0xF3CB4801,
	0x70165DF9,0x00D1C604,0x263673F9,0xD4B46410,0x32D90BD8,0xB7EA34FD,0xAC2462A4,0x4C5C7D50,
	0x0B5B99EE,0x96400138,0x3D1D1378,0x5A9DE9D8,0xE61164FC,0x7C06F351,0x71055B45,0x82821809,
	0x62D0E98D,0x4CB3B8CC,0x9800F975,0xDDA955BD,0x74412FCA,0x06DC9A73,0x10A9850C,0xC2F4AD55,
	0x2B72042F,0x456E6146,0xEA637EF4,0xDC463587,0xB3C44B74,0xB5DC4B08,0xCA570CE9,0xB3904E11,
	0x73CC2D70,0xF91D339B,0xFA4EF345,0xBE25DA78,0x4504A9F8,0x19ECC31B,0xF0287D6C,0x74E2B5E5,
	0xCD496959,0x5F57FABC,0xE8B3EDAC,0xB5CD8D87,0xDE2BEFF5,0xB83DF0BA,0xD57E6579,0x067F87BC,
	0x50052441,0x403DA47D,0x42A49BE2,0x6A773290,0x874B5920,0x1C0E6774,0xD8ED30FE,0xB8506AEE, 0
};

static u8					skype_I_hash[8] = {0x63,0x2F,0xE5,0xFD,0xE1,0x11,0x1B,0xD5};
static u8					skype_O_hash[8] = {0xAB,0x11,0xC5,0x85,0x03,0x63,0x9F,0x89};

// includes LEGACY addresses now as routable
static u8					allocated_ip_range[256] =	// latest official table from IANA
{
	0,0,0,1,1,0,1,1,1,1,0,1,1,1,0,1, 1,1,1,1,1,1,1,0,1,1,1,0,1,1,1,0,	//   0- 31
	1,1,1,1,0,0,1,0,1,1,0,1,1,1,0,1, 1,0,0,1,1,1,1,1,1,1,1,1,1,1,1,1,	//  32- 63
	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,	//  64- 95
	1,1,1,1,0,0,0,0,0,0,0,0,1,1,1,1, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,	//  96-127
	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,	// 128-159
	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0, 0,0,1,0,0,0,0,0,1,0,1,1,1,1,1,1,	// 160-191
	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,	// 192-223
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0	// 224-255
};

static u32 is_ip_routable (const u32 ip)
{
	if (!allocated_ip_range[ip & 0xFF]) return 0;	// ?.*.*.* => 0
	return ((ip>>24)-1) < 254;	// *.*.*.1-254 are ok => 1, .0 and .255 are not => 0
}

static u32 valid_rand (u32 mr, const u32 nr) {u32 i=16;for(;i&&((mr=skrand(mr))!=nr);i--);return mr==nr;}	// speeds up packet detection

static u32 bitcount (const void *x, const size_t b, const u32 mask)
{
	u32					i, n = 0;
	for (i = 0; i < b/4; i++) n += popcnt32(dword(x,i)&mask);
	if (b&3) n += popcnt32(dword(x,i)&mask&((1<<((b&3)<<3))-1));
	return n;
}

typedef struct _skype_user
{
	char	*user_name;				// "johnfuckingdoe"
	char	*password;				// "password"
	char	*email_sha1;			// ASCII SHA-1 of user->email hashed in UTF-32 for some reason
	char	*full_name;				// "John F Doe"
	char	*email;					// "john.f.doe@somewhere.online"
	char	*skype_version;			// "4.1.0.130"
	char	*language;				// "en"
	char	*country;				// "au"
	char	*state;					// "QLD"
	char	*city;					// "Cairns"
	u32		*location;				// user-signed user location
	u32		flag;					// 0/1
	u32		skype_id[2];			// a [random? unique?] 64-bit Skype ID
	u32		secret_p[17];			// secret 512-bit RSA prime P
	u32		secret_q[17];			// secret 512-bit RSA prime Q
	u32		public_key[33];			// public 1024-bit RSA modulus P*Q
	u32		secret_key[33];			// 0x10001 inverse modulo (P-1)*(Q-1)
	u32		credentials[65];		// server-signed user credentials
	u32		ip[3], server_ip;		// last known
	u16		port[3], server_port;	// last known
	u32		credentials_sha1[5];	// SHA1(00 00 00 01 user->credentials)
} skype_user;

typedef struct _node
{
	u8						ip[4];	// supernode IP address
	u32						port;	// supernode port
} node;


typedef struct _skype_thing
{
	u32						type, id, m, n;
} skype_thing;

typedef struct _skype_list
{
	struct _skype_list		*owner;
	skype_thing				*thing;
	u32						allocated_things;
	u32						things;
} skype_list;

#define renew(addr,size)	((addr)=realloc(addr,size))

static void free_user (skype_user *user)
{
	if (user->user_name) free (user->user_name);
	if (user->password) free (user->password);
	if (user->full_name) free (user->full_name);
	if (user->email) free (user->email);
	if (user->skype_version) free (user->skype_version);
	if (user->language) free (user->language);
	if (user->state) free (user->state);
	if (user->country) free (user->country);
	if (user->location) free (user->location);
	memset (user, 0, sizeof (*user));
}

// Debugging Stuff

#include <stdio.h>

static void bindump (const void *x, const u32 n)
{
	u32					i, j, m = (n+15)&~16;
	const u8			*b = (u8*)x;
	
	printf ("%d bytes:\n\n", n);
	for (i = 0; i < m; i++)
	{
		if ((i&15)==0) printf ("%04X:", i);
		if (i < n) printf (" %02X", b[i]); else printf ("   ");
		if ((i&15)==15)
		{
			printf (" | ");
			for (j = 0; j < 16; j++) printf ("%c", (i-15+j >= n) ? 0x20 : (b[i-15+j]<0x20)||(b[i-15+j]>0x7E) ? '.' : b[i-15+j]);
			printf (" |\n");
		}
	}
	printf ("\n\n");
}

#endif
