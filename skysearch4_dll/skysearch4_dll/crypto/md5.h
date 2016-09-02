// Ruptor's 128-bit MD5 hash (breakable) in pure C

#ifndef _md5_h_
#define _md5_h_


#include "../skype/skype_basics.h"


//! \brief MD5 hash output size in bits
#define MD5_HASH_BITS		128
//! \brief MD5 hash block size in bits
#define MD5_BLOCK_BITS		512

//! \brief MD5 hash output size in 32-bit words (4 words)
#define MD5_HASH_WORDS		((MD5_HASH_BITS + 31) / 32)
//! \brief MD5 hash block size in 32-bit words (16 words)
#define MD5_BLOCK_WORDS		((MD5_BLOCK_BITS + 31) / 32)
//! \brief MD5 hash output size in bytes (16 byte)
#define MD5_HASH_BYTES		(MD5_HASH_WORDS * 4)
//! \brief MD5 hash block size in bytes (64 byte)
#define MD5_BLOCK_BYTES		(MD5_BLOCK_WORDS * 4)

#define MD5_LAST_BLOCK_BITS		(MD5_BLOCK_BITS - 64)
#define MD5_LAST_BLOCK_BYTES	(MD5_LAST_BLOCK_BITS / 8)
#define MD5_LAST_BLOCK_WORDS	(MD5_LAST_BLOCK_BYTES / sizeof (long))

#define MD5_ADD					(MD5->hash[0] += A, MD5->hash[1] += B, MD5->hash[2] += C, MD5->hash[3] += D)

#define MD5_R0(a,b,c,d,k,s,t)	(a += ((k)+(t)+((((c)^(d))&(b))^(d))), a = rotl32 (a, s), a += b)
#define MD5_R1(a,b,c,d,k,s,t)	(a += ((k)+(t)+((((b)^(c))&(d))^(c))), a = rotl32 (a, s), a += b)
#define MD5_R2(a,b,c,d,k,s,t)	(a += ((k)+(t)+((b)^(c)^(d))), a = rotl32 (a, s), a += b)
#define MD5_R3(a,b,c,d,k,s,t)	(a += ((k)+(t)+(((~(d))|(b))^(c))), a = rotl32 (a, s), a += b)

//! \brief MD5 context structure containing the intermediate state while calculating a hash of multiple blocks of data of variable size
typedef struct _MD5_state
{
	//! \brief Message hash
	u32			hash[MD5_HASH_WORDS];
	//! \brief Last hashed block position
	u32			pos;
	//! \brief 64-bit bit count
	u32			bits[2];
	//! \brief MD5 data buffer
	u32			data[MD5_BLOCK_WORDS];
} MD5_state;

//! \brief Initial values to assign to a locally defined MD5 state to avoid calling MD5_init at run time
#define MD5_INIT { {0x67452301U, 0xEFCDAB89U, 0x98BADCFEU, 0x10325476U}, 0, {0} }

//! Called once to initialize MD5 context internal state for subsequent calls to MD5_update and MD5_end.
//! \brief initializes MD5 context internal state
//! \retval MD5_context initialized with standard values
static __inline__ void MD5_init (MD5_state *MD5_context) { MD5_context->hash[0] = 0x67452301UL; MD5_context->hash[1] = 0xEFCDAB89UL; MD5_context->hash[2] = 0x98BADCFEUL; MD5_context->hash[3] = 0x10325476UL; MD5_context->pos = 0; MD5_context->bits[0] = 0; MD5_context->bits[1] = 0; }

//! \brief updates MD5 internal state by hashing in a data block of specified arbitrary length
//! \pre MD5_context has to be initialized with MD5_INIT values or by MD5_init or by a previous call to MD5_update
//! \pre the source has to be converted to the network byte order or LSF byte order before hashing (see make_LSF)
//! \post the hash in MD5_context is incomplete until a call to MD5_end
//! \param data the actual data to be hashed in
//! \param bytes length in bytes of the data to be hashed in
//! \retval MD5_context is updated
extern void MD5_update (MD5_state *MD5_context, const void *data, u32 bytes);

//! \brief finalizes MD5 internal state resulting in a 128-bit (16-byte) MD5 hash
//! \pre MD5_context has to be initialized with MD5_INIT values or by MD5_init or by a previous call to MD5_update
//! \post MD5_context contains the final MD5_HASH_BYTES (16) byte long 128-bit hash in MD5_contest->hash
extern void MD5_end (MD5_state *MD5_context);

//! To be used on single strings or single blobs of data. To hash multiple strings or multiple blocks use MD5_init, MD5_update and MD5_end functions instead.
//! \brief calculates MD5 hash of a single block of data of specified length
//! \param data the actual data to be hashed in (in network byte order or in LSF byte order)
//! \param bytes length in bytes of the data to be hashed in
//! \retval hash contains final MD5_HASH_BYTES (16) byte long 128-bit MD5 hash of the specified data
extern void MD5_hash (const void *data, u32 bytes, void *hash);

extern void MD5_block (MD5_state *MD5, u32 *X);

#endif
