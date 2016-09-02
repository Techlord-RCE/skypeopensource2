// Ruptor's 160-bit SHA1 hash (breakable) in pure C

#include <string.h>
#include "sha1.h"

static void SHA1_block (SHA1_state *SHA1, const u32 *data)
{
	u32					blk[80];
	register u32		a, b, c, d, e;
	
	// Step A.	Copy the data buffer into the local work buffer
	memcpy (blk, data, SHA1_BLOCK_BYTES);
	
	// Step B.	Expand the 16 words into 64 more temporary data words
	SHA1_expand (16); SHA1_expand (17); SHA1_expand (18); SHA1_expand (19); SHA1_expand (20);
	SHA1_expand (21); SHA1_expand (22); SHA1_expand (23); SHA1_expand (24); SHA1_expand (25);
	SHA1_expand (26); SHA1_expand (27); SHA1_expand (28); SHA1_expand (29); SHA1_expand (30);
	SHA1_expand (31); SHA1_expand (32); SHA1_expand (33); SHA1_expand (34); SHA1_expand (35);
	SHA1_expand (36); SHA1_expand (37); SHA1_expand (38); SHA1_expand (39); SHA1_expand (40);
	SHA1_expand (41); SHA1_expand (42); SHA1_expand (43); SHA1_expand (44); SHA1_expand (45);
	SHA1_expand (46); SHA1_expand (47); SHA1_expand (48); SHA1_expand (49); SHA1_expand (50);
	SHA1_expand (51); SHA1_expand (52); SHA1_expand (53); SHA1_expand (54); SHA1_expand (55);
	SHA1_expand (56); SHA1_expand (57); SHA1_expand (58); SHA1_expand (59); SHA1_expand (60);
	SHA1_expand (61); SHA1_expand (62); SHA1_expand (63); SHA1_expand (64); SHA1_expand (65);
	SHA1_expand (66); SHA1_expand (67); SHA1_expand (68); SHA1_expand (69); SHA1_expand (70);
	SHA1_expand (71); SHA1_expand (72); SHA1_expand (73); SHA1_expand (74); SHA1_expand (75);
	SHA1_expand (76); SHA1_expand (77); SHA1_expand (78); SHA1_expand (79);
	
	// Step C.	Set up first buffer
	a = SHA1->hash[0], b = SHA1->hash[1], c = SHA1->hash[2], d = SHA1->hash[3], e = SHA1->hash[4];
	
	// Step D. SHA1 register mangling divided into 4 sub-rounds
	SHA1_R0 (a,b,c,d,e, 0); SHA1_R0 (e,a,b,c,d, 1); SHA1_R0 (d,e,a,b,c, 2); SHA1_R0 (c,d,e,a,b, 3); SHA1_R0 (b,c,d,e,a, 4);
	SHA1_R0 (a,b,c,d,e, 5); SHA1_R0 (e,a,b,c,d, 6); SHA1_R0 (d,e,a,b,c, 7); SHA1_R0 (c,d,e,a,b, 8); SHA1_R0 (b,c,d,e,a, 9);
	SHA1_R0 (a,b,c,d,e,10); SHA1_R0 (e,a,b,c,d,11); SHA1_R0 (d,e,a,b,c,12); SHA1_R0 (c,d,e,a,b,13); SHA1_R0 (b,c,d,e,a,14);
	SHA1_R0 (a,b,c,d,e,15); SHA1_R0 (e,a,b,c,d,16); SHA1_R0 (d,e,a,b,c,17); SHA1_R0 (c,d,e,a,b,18); SHA1_R0 (b,c,d,e,a,19);
	SHA1_R1 (a,b,c,d,e,20); SHA1_R1 (e,a,b,c,d,21); SHA1_R1 (d,e,a,b,c,22); SHA1_R1 (c,d,e,a,b,23); SHA1_R1 (b,c,d,e,a,24);
	SHA1_R1 (a,b,c,d,e,25); SHA1_R1 (e,a,b,c,d,26); SHA1_R1 (d,e,a,b,c,27); SHA1_R1 (c,d,e,a,b,28); SHA1_R1 (b,c,d,e,a,29);
	SHA1_R1 (a,b,c,d,e,30); SHA1_R1 (e,a,b,c,d,31); SHA1_R1 (d,e,a,b,c,32); SHA1_R1 (c,d,e,a,b,33); SHA1_R1 (b,c,d,e,a,34);
	SHA1_R1 (a,b,c,d,e,35); SHA1_R1 (e,a,b,c,d,36); SHA1_R1 (d,e,a,b,c,37); SHA1_R1 (c,d,e,a,b,38); SHA1_R1 (b,c,d,e,a,39);
	SHA1_R2 (a,b,c,d,e,40); SHA1_R2 (e,a,b,c,d,41); SHA1_R2 (d,e,a,b,c,42); SHA1_R2 (c,d,e,a,b,43); SHA1_R2 (b,c,d,e,a,44);
	SHA1_R2 (a,b,c,d,e,45); SHA1_R2 (e,a,b,c,d,46); SHA1_R2 (d,e,a,b,c,47); SHA1_R2 (c,d,e,a,b,48); SHA1_R2 (b,c,d,e,a,49);
	SHA1_R2 (a,b,c,d,e,50); SHA1_R2 (e,a,b,c,d,51); SHA1_R2 (d,e,a,b,c,52); SHA1_R2 (c,d,e,a,b,53); SHA1_R2 (b,c,d,e,a,54);
	SHA1_R2 (a,b,c,d,e,55); SHA1_R2 (e,a,b,c,d,56); SHA1_R2 (d,e,a,b,c,57); SHA1_R2 (c,d,e,a,b,58); SHA1_R2 (b,c,d,e,a,59);
	SHA1_R3 (a,b,c,d,e,60); SHA1_R3 (e,a,b,c,d,61); SHA1_R3 (d,e,a,b,c,62); SHA1_R3 (c,d,e,a,b,63); SHA1_R3 (b,c,d,e,a,64);
	SHA1_R3 (a,b,c,d,e,65); SHA1_R3 (e,a,b,c,d,66); SHA1_R3 (d,e,a,b,c,67); SHA1_R3 (c,d,e,a,b,68); SHA1_R3 (b,c,d,e,a,69);
	SHA1_R3 (a,b,c,d,e,70); SHA1_R3 (e,a,b,c,d,71); SHA1_R3 (d,e,a,b,c,72); SHA1_R3 (c,d,e,a,b,73); SHA1_R3 (b,c,d,e,a,74);
	SHA1_R3 (a,b,c,d,e,75); SHA1_R3 (e,a,b,c,d,76); SHA1_R3 (d,e,a,b,c,77); SHA1_R3 (c,d,e,a,b,78); SHA1_R3 (b,c,d,e,a,79);
	
	// Step E.	Build message hash
	SHA1_ADD (a,b,c,d,e);
}

void SHA1_update (SHA1_state *SHA1, const void *data, u32 bytes)
{
	register u32		i;
	const u8			*data8 = data;
	
	if (bytes == 0) return;
	SHA1->bits[0] += bytes*8;
	SHA1->bits[1] += (SHA1->bits[0]<bytes*8);
	for (i = SHA1_BLOCK_BYTES - SHA1->pos; bytes >= i; i = SHA1_BLOCK_BYTES, SHA1->pos = 0)
	{
		memcpy (((u8*)SHA1->data)+SHA1->pos, data8, i);
		bytes -= i;
		data8 += i;
		make_MSF_32 (SHA1->data, SHA1_BLOCK_WORDS);
		SHA1_block (SHA1, SHA1->data);
	}
	memcpy (((u8*)SHA1->data)+SHA1->pos, data8, bytes);
	SHA1->pos += bytes;
}

void SHA1_end (SHA1_state *SHA1)
{
	u32					PADDED_BLOCK[SHA1_BLOCK_WORDS];
	register u32		i = SHA1->pos;
	
	byte(SHA1->data,i) = 0x80, i++;
	if (i <= SHA1_LAST_BLOCK_BYTES)
	{
		memset (((u8*)SHA1->data)+i, 0, SHA1_LAST_BLOCK_BYTES - i);
		make_MSF_32 (SHA1->data, (i+3) >> 2);
		SHA1->data[SHA1_BLOCK_WORDS-2] = SHA1->bits[ord2(1)];
		SHA1->data[SHA1_BLOCK_WORDS-1] = SHA1->bits[ord2(0)];
		SHA1_block (SHA1, SHA1->data);
	}
	else
	{
		memset (((u8*)SHA1->data)+i, 0, SHA1_BLOCK_BYTES - i);
		make_MSF_32 (SHA1->data, (i+3) >> 2);
		SHA1_block (SHA1, SHA1->data);
		memset (PADDED_BLOCK, 0, SHA1_BLOCK_BYTES - 8);
		PADDED_BLOCK[SHA1_BLOCK_WORDS-2] = SHA1->bits[ord2(1)];
		PADDED_BLOCK[SHA1_BLOCK_WORDS-1] = SHA1->bits[ord2(0)];
		SHA1_block (SHA1, PADDED_BLOCK);
	}
	make_LSF_32 (SHA1->hash, SHA1_HASH_WORDS);
}

void SHA1_hash (const void *data, u32 bytes, void *hash)
{
	SHA1_state			SHA1 = SHA1_INIT;
	const u8			*data8 = data;
	
	if (bytes) for (;;)
	{
		if (bytes <= SHA1_BLOCK_BYTES)
		{
			SHA1_update (&SHA1, data8, bytes);
			SHA1_end (&SHA1);
			break;
		}
		SHA1_update (&SHA1, data8, SHA1_BLOCK_BYTES);
		bytes -= SHA1_BLOCK_BYTES;
		data8 += SHA1_BLOCK_BYTES;
	}
	memcpy (hash, (u8*) SHA1.hash, 20);
}
