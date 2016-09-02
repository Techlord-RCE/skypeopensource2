// Ruptor's 128-bit MD5 hash (breakable) in pure C

#include <string.h>
#include "md5.h"

static u8 local_md[MD5_HASH_BYTES];

void MD5_block (MD5_state *MD5, u32 *X)
{
	register u32		A = MD5->hash[0];
	register u32		B = MD5->hash[1];
	register u32		C = MD5->hash[2];
	register u32		D = MD5->hash[3];
	
	MD5_R0(A,B,C,D,X[ 0], 7,0xd76aa478L);
	MD5_R0(D,A,B,C,X[ 1],12,0xe8c7b756L);
	MD5_R0(C,D,A,B,X[ 2],17,0x242070dbL);
	MD5_R0(B,C,D,A,X[ 3],22,0xc1bdceeeL);
	MD5_R0(A,B,C,D,X[ 4], 7,0xf57c0fafL);
	MD5_R0(D,A,B,C,X[ 5],12,0x4787c62aL);
	MD5_R0(C,D,A,B,X[ 6],17,0xa8304613L);
	MD5_R0(B,C,D,A,X[ 7],22,0xfd469501L);
	MD5_R0(A,B,C,D,X[ 8], 7,0x698098d8L);
	MD5_R0(D,A,B,C,X[ 9],12,0x8b44f7afL);
	MD5_R0(C,D,A,B,X[10],17,0xffff5bb1L);
	MD5_R0(B,C,D,A,X[11],22,0x895cd7beL);
	MD5_R0(A,B,C,D,X[12], 7,0x6b901122L);
	MD5_R0(D,A,B,C,X[13],12,0xfd987193L);
	MD5_R0(C,D,A,B,X[14],17,0xa679438eL);
	MD5_R0(B,C,D,A,X[15],22,0x49b40821L);
	
	MD5_R1(A,B,C,D,X[ 1], 5,0xf61e2562L);
	MD5_R1(D,A,B,C,X[ 6], 9,0xc040b340L);
	MD5_R1(C,D,A,B,X[11],14,0x265e5a51L);
	MD5_R1(B,C,D,A,X[ 0],20,0xe9b6c7aaL);
	MD5_R1(A,B,C,D,X[ 5], 5,0xd62f105dL);
	MD5_R1(D,A,B,C,X[10], 9,0x02441453L);
	MD5_R1(C,D,A,B,X[15],14,0xd8a1e681L);
	MD5_R1(B,C,D,A,X[ 4],20,0xe7d3fbc8L);
	MD5_R1(A,B,C,D,X[ 9], 5,0x21e1cde6L);
	MD5_R1(D,A,B,C,X[14], 9,0xc33707d6L);
	MD5_R1(C,D,A,B,X[ 3],14,0xf4d50d87L);
	MD5_R1(B,C,D,A,X[ 8],20,0x455a14edL);
	MD5_R1(A,B,C,D,X[13], 5,0xa9e3e905L);
	MD5_R1(D,A,B,C,X[ 2], 9,0xfcefa3f8L);
	MD5_R1(C,D,A,B,X[ 7],14,0x676f02d9L);
	MD5_R1(B,C,D,A,X[12],20,0x8d2a4c8aL);
	
	MD5_R2(A,B,C,D,X[ 5], 4,0xfffa3942L);
	MD5_R2(D,A,B,C,X[ 8],11,0x8771f681L);
	MD5_R2(C,D,A,B,X[11],16,0x6d9d6122L);
	MD5_R2(B,C,D,A,X[14],23,0xfde5380cL);
	MD5_R2(A,B,C,D,X[ 1], 4,0xa4beea44L);
	MD5_R2(D,A,B,C,X[ 4],11,0x4bdecfa9L);
	MD5_R2(C,D,A,B,X[ 7],16,0xf6bb4b60L);
	MD5_R2(B,C,D,A,X[10],23,0xbebfbc70L);
	MD5_R2(A,B,C,D,X[13], 4,0x289b7ec6L);
	MD5_R2(D,A,B,C,X[ 0],11,0xeaa127faL);
	MD5_R2(C,D,A,B,X[ 3],16,0xd4ef3085L);
	MD5_R2(B,C,D,A,X[ 6],23,0x04881d05L);
	MD5_R2(A,B,C,D,X[ 9], 4,0xd9d4d039L);
	MD5_R2(D,A,B,C,X[12],11,0xe6db99e5L);
	MD5_R2(C,D,A,B,X[15],16,0x1fa27cf8L);
	MD5_R2(B,C,D,A,X[ 2],23,0xc4ac5665L);
	
	MD5_R3(A,B,C,D,X[ 0], 6,0xf4292244L);
	MD5_R3(D,A,B,C,X[ 7],10,0x432aff97L);
	MD5_R3(C,D,A,B,X[14],15,0xab9423a7L);
	MD5_R3(B,C,D,A,X[ 5],21,0xfc93a039L);
	MD5_R3(A,B,C,D,X[12], 6,0x655b59c3L);
	MD5_R3(D,A,B,C,X[ 3],10,0x8f0ccc92L);
	MD5_R3(C,D,A,B,X[10],15,0xffeff47dL);
	MD5_R3(B,C,D,A,X[ 1],21,0x85845dd1L);
	MD5_R3(A,B,C,D,X[ 8], 6,0x6fa87e4fL);
	MD5_R3(D,A,B,C,X[15],10,0xfe2ce6e0L);
	MD5_R3(C,D,A,B,X[ 6],15,0xa3014314L);
	MD5_R3(B,C,D,A,X[13],21,0x4e0811a1L);
	MD5_R3(A,B,C,D,X[ 4], 6,0xf7537e82L);
	MD5_R3(D,A,B,C,X[11],10,0xbd3af235L);
	MD5_R3(C,D,A,B,X[ 2],15,0x2ad7d2bbL);
	MD5_R3(B,C,D,A,X[ 9],21,0xeb86d391L);
	
	MD5->pos = 0;
	MD5_ADD;
}

void MD5_update (MD5_state *MD5, const void *data, u32 bytes)
{
	register u32		i;
	const u8			*data8 = data;
	
	if (bytes == 0) return;
	MD5->bits[0] += bytes*8;
	MD5->bits[1] += (MD5->bits[0] < bytes*8);
	for (i = MD5_BLOCK_BYTES - MD5->pos; bytes >= i; i = MD5_BLOCK_BYTES)
	{
		memcpy (&byte(MD5->data,MD5->pos), data8, i);
		bytes -= i;
		data8 += i;
		make_LSF_32 (MD5->data, MD5_BLOCK_WORDS);
		MD5_block (MD5, MD5->data);
	}
	memcpy (&byte(MD5->data,MD5->pos), data8, bytes);
	MD5->pos += bytes;
}

void MD5_end (MD5_state *MD5)
{
	u32					PADDED_BLOCK[MD5_BLOCK_WORDS];
	register u32		i = MD5->pos;
	
	byte(MD5->data,i) = 0x80, i++;
	if (i <= MD5_LAST_BLOCK_BYTES)
	{
		memset (&byte(MD5->data,i), 0, MD5_LAST_BLOCK_BYTES - i);
		make_LSF_32 (MD5->data, (i+3) >> 2);
		MD5->data[MD5_BLOCK_WORDS-2] = MD5->bits[ord2(0)];
		MD5->data[MD5_BLOCK_WORDS-1] = MD5->bits[ord2(1)];
		MD5_block (MD5, MD5->data);
	}
	else
	{
		memset (&byte(MD5->data,i), 0, MD5_BLOCK_BYTES - i);
		make_LSF_32 (MD5->data, (i+3) >> 2);
		MD5_block (MD5, MD5->data);
		memset (PADDED_BLOCK, 0, MD5_BLOCK_BYTES - 8);
		PADDED_BLOCK[MD5_BLOCK_WORDS-2] = MD5->bits[ord2(0)];
		PADDED_BLOCK[MD5_BLOCK_WORDS-1] = MD5->bits[ord2(1)];
		MD5_block (MD5, PADDED_BLOCK);
	}
	make_LSF_32 (MD5->hash, MD5_HASH_WORDS);
}

void MD5_hash (const void *data, u32 bytes, void *hash)
{
	MD5_state			MD5 = MD5_INIT;
	const u8			*data8 = data;
	
	if (bytes) for (;;)
	{
		if (bytes <= MD5_BLOCK_BYTES)
		{
			MD5_update (&MD5, data8, bytes);
			MD5_end (&MD5);
			break;
		}
		MD5_update (&MD5, data8, MD5_BLOCK_BYTES);
		bytes -= MD5_BLOCK_BYTES;
		data8 += MD5_BLOCK_BYTES;
	}
	memcpy (hash, (u8*)MD5.hash, MD5_HASH_BYTES);
}
