// Ruptor's 160-bit SHA1 hash (breakable) in pure C

#ifndef _sha1_h_
#define _sha1_h_

/*!
	SHA1-0/SHA1-1 hash function, set to SHA1-1 at present
	#define SHA1_v 0 in <crypto/sha1/sha1.c> or turn it into a variable to calculate the original SHA1-0
!*/


#include "../skype/skype_basics.h"


//! \brief SHA1 hash output size in bits
#define SHA1_HASH_BITS			160
//! \brief SHA1 hash block size in bits
#define SHA1_BLOCK_BITS			512

//! \brief SHA1 hash output size in 32-bit words (5 words)
#define SHA1_HASH_WORDS			((SHA1_HASH_BITS + 31) / 32)
//! \brief SHA1 hash block size in 32-bit words (16 words)
#define SHA1_BLOCK_WORDS		((SHA1_BLOCK_BITS + 31) / 32)
//! \brief SHA1 hash output size in bytes (20 byte)
#define SHA1_HASH_BYTES			(SHA1_HASH_WORDS * 4)
//! \brief SHA1 hash block size in bytes (64 byte)
#define SHA1_BLOCK_BYTES		(SHA1_BLOCK_WORDS * 4)

#define SHA1_v					1	// 1 for SHA1-1, 0 for the original SHA1, or make it variable

#define SHA1_LAST_BLOCK_BITS	(SHA1_BLOCK_BITS - 64)
#define SHA1_LAST_BLOCK_WORDS	((SHA1_LAST_BLOCK_BITS + 31) / 32)
#define SHA1_LAST_BLOCK_BYTES	(SHA1_LAST_BLOCK_WORDS * 4)

// The initial expansion function

#define SHA1_expand(i)			blk[i] = rotl32 (blk[i-3] ^ blk[i-8] ^ blk[i-14] ^ blk[i-16], SHA1_v)

// The four SHA1 sub-rounds

#define SHA1_ADD(a,b,c,d,e)		(SHA1->hash[0] += a, SHA1->hash[1] += b, SHA1->hash[2] += c, SHA1->hash[3] += d, SHA1->hash[4] += e)

#define SHA1_R0(v,w,x,y,z,i)	(z += blk[i] + 0x5A827999 + rotl32 (v, 5) + ((w&(x^y))^y)    , w = rotl32 (w, 30))
#define SHA1_R1(v,w,x,y,z,i)	(z += blk[i] + 0x6ED9EBA1 + rotl32 (v, 5) + (w^x^y)          , w = rotl32 (w, 30))
#define SHA1_R2(v,w,x,y,z,i)	(z += blk[i] + 0x8F1BBCDC + rotl32 (v, 5) + (((w|x)&y)|(w&x)), w = rotl32 (w, 30))
#define SHA1_R3(v,w,x,y,z,i)	(z += blk[i] + 0xCA62C1D6 + rotl32 (v, 5) + (w^x^y)          , w = rotl32 (w, 30))

//! \brief SHA1 context structure containing the intermediate state while calculating a hash of multiple blocks of data of variable size
typedef struct _SHA1_state
{
	//! \brief Message hash
	u32			hash[SHA1_HASH_WORDS];
	//! \brief Last hashed block position
	u32			pos;
	//! \brief 64-bit bit count
	u32			bits[2];
	//! \brief SHA1_context data buffer
	u32			data[SHA1_BLOCK_WORDS];
} SHA1_state;

//! \brief Initial values to assign to a locally defined SHA1 state to avoid calling SHA1_init at run time
#define SHA1_INIT { {0x67452301UL, 0xEFCDAB89UL, 0x98BADCFEUL, 0x10325476UL, 0xC3D2E1F0UL}, 0, {0} }

//! Called once to initialize SHA1 context internal state for subsequent calls to SHA1_update and SHA1_end.
//! \brief initializes SHA1 context internal state
//! \retval SHA1_context initialized with standard values
static __inline__ void SHA1_init (SHA1_state *SHA1_context) { SHA1_context->hash[0] = 0x67452301UL; SHA1_context->hash[1] = 0xEFCDAB89UL; SHA1_context->hash[2] = 0x98BADCFEUL; SHA1_context->hash[3] = 0x10325476UL; SHA1_context->hash[4] = 0xC3D2E1F0UL; SHA1_context->pos = 0; SHA1_context->bits[0] = 0; SHA1_context->bits[1] = 0; }

//! \brief updates SHA1 internal state by hashing in a data block of specified arbitrary length
//! \pre SHA1_context has to be initialized with SHA1_INIT values or by SHA1_init or by a previous call to SHA1_update
//! \pre the source has to be converted to the network byte order or LSF byte order before hashing (see make_LSF)
//! \post the hash in SHA1_context is incomplete until a call to SHA1_end
//! \param data the actual data to be hashed in
//! \param bytes length in bytes of the data to be hashed in
//! \retval SHA1_context is updated
extern void SHA1_update (SHA1_state *SHA1_context, const void *data, u32 bytes);

//! \brief finalizes SHA1 internal state resulting in a SHA1_HASH_BITS (160) bit or SHA1_HASH_BYTES (20) byte long SHA1 hash
//! \pre SHA1_context has to be initialized with SHA1_INIT values or by SHA1_init or by a previous call to SHA1_update
//! \post SHA1_context contains the final SHA1_HASH_BYTES (20) byte long 160-bit SHA1 hash in SHA1_contest->hash
extern void SHA1_end (SHA1_state *SHA1_context);

//! To be used on single strings or single blobs of data. To hash multiple strings or multiple blocks use SHA1_init, SHA1_update and SHA1_end functions instead.
//! \brief calculates SHA1 hash of a single block of data of specified length
//! \param data the actual data to be hashed in (in network byte order or in LSF byte order)
//! \param bytes length in bytes of the data to be hashed in
//! \retval hash contains final SHA1_HASH_BYTES (20) byte long 160-bit SHA1 hash of the specified data
extern void SHA1_hash (const void *data, u32 bytes, void *hash);

#endif
