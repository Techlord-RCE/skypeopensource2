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

extern int unpack41_structure(char *buf, unsigned int buflen, char *selfptr);
extern int print_structure(char *str, char *selfptr, int detail);
extern int free_structure(char *selfptr);


struct blob_s {
	uint obj_type;
	uint obj_index;
	uint obj_data;
	uint data_ptr;
	uint data_size;
};


//
// main structure
//
struct self_s {

	uint session_id;
	uint session_cmd;

	// main buf decoded here
	char *heap_alloc_buf;
	uint heap_alloc_buf_count;


	// internal values
	uint value_02c3f818; //curr buf
	uint value_02c3f844; //buf len left
	uint value_02e09da0; //session cmd ptr
	uint value_02c3f7f8; //some struct ptr, addr on allocated heap allocated in it.
	uint value_02c3f83c; //counter of size of allocated buffer.. decremented in code.. from 0x04b000 = 307200
	uint value_02c3f7fc; //some struct ptr2 // ptr on ALLOC-ed buffer heap_alloc_buf
	uint value_02c3ed68; //sohranenniy schitanniy perviy byte of encoding stream, decoded

	uint value_02e2d438; //heap_alloc_struct , buffer for string in 0x41

	// some tmp buf, 0x14=20 byte long
	char *value_02c3ed70_ptr[0x14];

	//hz, some tmp util for re-enterance check
	uint run_mysub_unpack_7_bit_encoded;

	//new allocated structures while processing 0x41
	//maximum 100
	char *heap_alloc_struct_array[100*4];
	unsigned int heap_alloc_struct_array_size[100*4];
	uint heap_alloc_struct_count;

};

