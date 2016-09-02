// include file to 41 decode
//

#include <stdio.h>


#ifndef uint
    #define uint unsigned int
#endif
#ifndef u8
	#define u8 unsigned char
#endif
#ifndef u32
	#define u32 unsigned long
#endif


#define ROTR32(x, n)			((((u32) (x)) >> ((n) & 31)) | (((u32) (x)) << ((0-(n)) & 31)))
#define ROTL32(x, n)			((((u32) (x)) << ((n) & 31)) | (((u32) (x)) >> ((0-(n)) & 31)))
#define bswap32(x)				((ROTL32 ((u32) (x), 8) & 0x00FF00FFU) | (ROTR32 ((u32) (x), 8) & 0xFF00FF00U))


struct blob_s {
	uint obj_type;
	uint obj_index;
	uint obj_data;
	uint data_ptr;
	uint data_size;
};


