/*  
*
* Utils
*
* little help tools
*
*
*/

// for rc4
//#include "Expand_IV.h"

// for aes
#include "crypto/rijndael.h"

// for 41 
#include "decode41.h"

//#include "defs.h"

extern unsigned int Calculate_CRC32(char *crc32, int bytes);
extern int Calculate_CRC32_For41(char *a2, int a3);
extern int encode_to_7bit(char *buf, uint word, int limit);



extern u8 aes_key[0x20];
extern u32 REMOTE_SESSION_ID;
extern u32 LOCAL_SESSION_ID;


#define byte(x)				(*(u8 *)(x))
#define word(x)				(*(u16 *)(x))
#define dword(x)			(*(u32 *)(x))
#define qword(x)			(*(u64 *)(x))
#define bswap16(x)			((((x)>>8)&0xFF)+(((x)&0xFF)<<8))

//////////////////////
// Util             //
//////////////////////
int show_memory(char *mem, int len, char *text){
	int zz;
	int i;

	printf("%s\n",text);
	printf("Len: 0x%08X\n",len);

	zz=0;
	for(i=0;i<len;i++){
		printf("%02X ",mem[i] & 0xff);
		zz++;if (zz == 16) { zz=0; printf("\n ");};
	};
	printf("\n");

	return 0;
};





/////////////////////////////////////////
// get blk seq
/////////////////////////////////////////
int get_blkseq(char *data, int datalen) {
	int tmplen;
	int blkseq;
	u32 pkt_crc32;
	u32 frompkt;


	//data without crc32
	tmplen=datalen-2;

	//crc32 from pkt
	memcpy(&frompkt, data+tmplen, 2);
	frompkt=frompkt & 0xffff;

	//show_memory(data, tmplen, "CRC32(tmp)");

	//crc32 on aes encrypt
	pkt_crc32=Calculate_CRC32( (char *)data,tmplen);
	pkt_crc32=pkt_crc32 & 0xffff;
	blkseq=pkt_crc32 ^ frompkt;
	
	//printf("frompkt = %08X\n",frompkt);
	//printf("pkt_crc32 = %08X\n",pkt_crc32);
	printf("blkseq from remote = %08X\n",blkseq);


	return blkseq;

};

int first_bytes_correction(char *header, int header_len, char *buf, int buf_len){
	u32 pkt_crc32;
	u32 total;
	u32 last2b;
	int tmplen;
	char *ptr;

	// calculate for 4 and 5 byte fixing
	ptr=(char *)buf;
	tmplen=buf_len;
    

	pkt_crc32=Calculate_CRC32(ptr, tmplen);
	pkt_crc32=pkt_crc32 & 0xffff;
	printf("pkt block crc32=%08X\n",pkt_crc32);

	total=REMOTE_SESSION_ID<<1;
	printf("total=0x%08X\n",total);

	last2b=pkt_crc32 ^ total;
	printf("last2b=0x%08X\n",last2b);

	printf("encode len: 0x%08X\n",buf_len+3);

    //encode buf1 len
	// + 3 for 0x05 and 2 byte crc
	header_len=encode_to_7bit(header, (buf_len+3)*2+1, header_len);

	header[header_len]=0x05;
	header_len++;

	header[header_len]=(unsigned char ) ((last2b & 0x0000ff00) >> 8);
	header_len++;
	header[header_len]=(unsigned char ) (last2b & 0xff);
	header_len++;

	return header_len;

};


/////////////////////////////////////////
// aes crypt
/////////////////////////////////////////
int process_aes_crypt(char *data, int datalen, int usekey, int blkseq, int need_xor){	
	static u8 zero[32];
	static u32 ks[60];
	u32 blk[0x10];
	int j;
	int k;
	char *ptr;


	memset(ks,0,sizeof(ks));

	// if no key, use zero
	memset(zero,0,sizeof(zero));

	// use real key
	if (usekey){
		memcpy(zero,aes_key,0x20);
	};

	// setup key
	aes_256_setkey (zero, ks);
	
	// for debug aes encoding
	// print key material
	if (0) {
		ptr=(char *)ks;
		show_memory(ptr, 60*4, "KeyMat");
	};

	// setup control block
	memset (blk, 0, 0x10);

	//if using key, control block have local and remote session id data.
	if (usekey){
		blk[0]=LOCAL_SESSION_ID * 0x10000 + REMOTE_SESSION_ID;
	};
	
	// need xor session id in control block
	if (need_xor){
		blk[0]=blk[0] ^ 0xFFFFFFFF;
	};

	blk[1]=blk[0];
	blk[3]=blk[3] + (blkseq * 0x10000);
	

	show_memory(data, datalen, "Before AES crypt");

	// process aes crypt
	for (j = 0; j+16 < datalen; j += 16){
		aes_256_encrypt (blk, blk+4, ks);
		dword(data+j+ 0) ^= bswap32(blk[4]);
		dword(data+j+ 4) ^= bswap32(blk[5]);
		dword(data+j+ 8) ^= bswap32(blk[6]);
		dword(data+j+12) ^= bswap32(blk[7]);
		blk[3]++;
	};
	if (j < datalen){
		aes_256_encrypt (blk, blk+4, ks);
		for (k = 0; j < datalen; j++, k++) data[j] ^= ((u8 *)(blk+4))[k^3];
	};

	show_memory(data, datalen, "After AES crypt");


	return 0;

};


//
// Process aes
//
int process_aes(char *buf, int buf_len, int usekey, int blkseq, int need_xor){	
	u32 aes_checksum_crc32;
	u32 pkt_crc32;

	// Re-calculate 41 checksum(crc32)
	aes_checksum_crc32=Calculate_CRC32_For41(buf,buf_len);
	printf("aes_checksum_crc32=0x%08X\n",aes_checksum_crc32);
	aes_checksum_crc32=bswap16(aes_checksum_crc32);	
	memcpy(buf+buf_len,&aes_checksum_crc32,2);
	buf_len+=2;

	
	//aes encrypt block 3
	//blkseq=0x06;	
	process_aes_crypt(buf, buf_len, usekey, blkseq, need_xor);

	//crc32 after aes encrypt
	pkt_crc32=Calculate_CRC32( (char *)buf,buf_len);
	pkt_crc32=pkt_crc32 & 0xffff;
	pkt_crc32=pkt_crc32 ^ blkseq;
	printf("crc32(after aes crypt)=%08X\n",pkt_crc32);
	memcpy(buf+buf_len, &pkt_crc32, 2);
	buf_len+=2;

	return buf_len;

};



/*
*
*
* Get Packet Size
* 
* reading first bytes(1-3), while (byte <= 0x80)
* and return size of rest message or block
*
*
*/
//in ida called
//unpack_7_bit_encoded_to_dword
int get_packet_size(char *data,int len){
	unsigned int ebx, edi, esi, eax, ecx, ebp, edx;
	char *buf_eax;


	//printf("ENTER unpack_7_bit_encoded_to_dword \n");
	
	ebx=len;

	esi=0;
	edi=0;

	eax=ebx;

	// if len == 0 
	if (eax==0){
			printf("konchilsya buffer,smth like terra nova here, jmp hz kuda\n");
			exit(-1);
	};


	// len - 1 
	ecx=eax-1;
	ebx=ecx;
    
	//ptr on data buffer
	ebp=(int )data;

	do{
		eax=ebp;

		ecx=esi;

		esi=esi+7;

		buf_eax=(char *)eax;
		edx=buf_eax[0] & 0xff; //ptr

		//printf("readed byte edx=%X\n",edx);

		eax++;

		ebp=eax;

		eax=edx;

		eax=eax & 0x7f;
		eax=eax << ecx;

		ecx=edi;

		ecx=ecx | eax;

		edi=ecx;

	    //printf("accamulated int ecx=%X\n",ecx);

	}while(edx >= 0x80);  
	//loop, while byte readed from buf >=0x80


	// size specific
	// diveded by 2
	edi=edi>>1;

	printf("PKT SIZE=0x%08X\n",edi);


	//printf("LEAVE unpack_7_bit_encoded_to_dword \n");

	return edi;

};


int get_packet_size2(char *data, int len, int *header_len){
	unsigned int ebx, edi, esi, eax, ecx, ebp, edx;
	char *buf_eax;
	int buf_count;

	buf_count = 0;
	//printf("ENTER unpack_7_bit_encoded_to_dword \n");
	
	ebx=len;

	esi=0;
	edi=0;

	eax=ebx;

	// if len == 0 
	if (eax==0){
			printf("konchilsya buffer,smth like terra nova here, jmp hz kuda\n");
			exit(-1);
	};


	// len - 1 
	ecx=eax-1;
	ebx=ecx;
    
	//ptr on data buffer
	ebp=(int )data;

	do{
		eax=ebp;

		ecx=esi;

		esi=esi+7;

		buf_eax=(char *)eax;
		edx=buf_eax[0] & 0xff; //ptr

		//printf("readed byte edx=%X\n",edx);

		eax++;

		ebp=eax;

		buf_count++;

		eax=edx;

		eax=eax & 0x7f;
		eax=eax << ecx;

		ecx=edi;

		ecx=ecx | eax;

		edi=ecx;

	    //printf("accamulated int ecx=%X\n",ecx);

	}while(edx >= 0x80);  
	//loop, while byte readed from buf >=0x80


	// size specific
	// diveded by 2
	edi=edi>>1;

	printf("PKT SIZE=0x%08X\n",edi);
	printf("HEADER_LEN SIZE=0x%08X\n",buf_count);

	if (1) {
		int h_len = buf_count;
		int t_len = edi;

		if (h_len == 0){
			printf("pkt header_len wrong, len: 0x%08X\n", h_len);
			exit(1);
		};
		if (h_len > 3){
			printf("pkt header_len wrong, len: 0x%08X\n", h_len);
			exit(1);
		};
		if (t_len > 0x1000){
			printf("pkt block size too big, len: 0x%08X\n",t_len);
			exit(1);
		};
		if (t_len <= 0){
			printf("pkt block size too small, len: 0x%08X\n",t_len);
			exit(1);
		};
	};


	//printf("LEAVE unpack_7_bit_encoded_to_dword \n");

	*header_len = buf_count;

	return edi;
};



int get_packet_size3(char *data, int len, int *header_len){
	unsigned int ebx, edi, esi, eax, ecx, ebp, edx;
	char *buf_eax;
	int buf_count;

	buf_count = 0;
	//printf("ENTER unpack_7_bit_encoded_to_dword \n");
	
	ebx=len;

	esi=0;
	edi=0;

	eax=ebx;

	// if len == 0 
	if (eax==0){
			printf("konchilsya buffer,smth like terra nova here, jmp hz kuda\n");
			exit(-1);
	};


	// len - 1 
	ecx=eax-1;
	ebx=ecx;
    
	//ptr on data buffer
	ebp=(int )data;

	do{
		eax=ebp;

		ecx=esi;

		esi=esi+7;

		buf_eax=(char *)eax;
		edx=buf_eax[0] & 0xff; //ptr

		//printf("readed byte edx=%X\n",edx);

		eax++;

		ebp=eax;

		buf_count++;

		eax=edx;

		eax=eax & 0x7f;
		eax=eax << ecx;

		ecx=edi;

		ecx=ecx | eax;

		edi=ecx;

	    //printf("accamulated int ecx=%X\n",ecx);

	}while(edx >= 0x80);  
	//loop, while byte readed from buf >=0x80


	// size specific
	// diveded by 2
	edi=edi>>1;

	printf("AES_DATA_ID=0x%08X\n",edi);
	printf("AES_DATA_ID_LEN SIZE=0x%08X\n",buf_count);

	if (1) {
		int h_len = buf_count;
		int t_len = edi;

		if (h_len == 0){
			printf("pkt header_len wrong, len: 0x%08X\n", h_len);
			exit(1);
		};
		if (h_len > 3){
			printf("pkt header_len wrong, len: 0x%08X\n", h_len);
			exit(1);
		};
		if (t_len > 0x10000){
			printf("pkt block size too big, len: 0x%08X\n",t_len);
			exit(1);
		};
		if (t_len < 0){
			printf("pkt block size too small, len: 0x%08X\n",t_len);
			exit(1);
		};
	};


	//printf("LEAVE unpack_7_bit_encoded_to_dword \n");

	*header_len = buf_count;

	return edi;
};



int set_packet_size(char *a1, int c){
  char *block;
  unsigned int b;


  b = c;
  for ( block = a1; b > 0x7F; ++*block )
  {
    *block = (char)b | 0x80;
	printf("1 cikl,  block[0]=0x%08X block[1]=0x%08X block[2]=0x%08X\n",block[0],block[1],block[2]);
    b >>= 7;
  }
  
  printf("2 aft, block[0]=0x%08X block[1]=0x%08X block[2]=0x%08X\n",block[0],block[1],block[2]);
  *block++;
  printf("3 inc, block[0]=0x%08X block[1]=0x%08X block[2]=0x%08X\n",block[0],block[1],block[2]);

  *block=b;

  printf("4 set, block[0]=0x%08X block[1]=0x%08X block[2]=0x%08X\n",block[0],block[1],block[2]);
  //*block--;
  *block--;

  printf("5 back,block[0]=0x%08X block[1]=0x%08X block[2]=0x%08X\n",block[0],block[1],block[2]);


  return 0;
}


//
// Encode bytes to 7 bit
//
int encode_to_7bit(char *buf, uint word, int limit){
	uint to[10];
	int i;
	int n;
	uint a;


	n=0;
	for(i=0;i<10;i++){
		to[i]=0;
	};


    for (a = word; a > 0x7F; a >>= 7, n++){ 
		
		if (n > 10) {
			printf("7bit encoding fail\n");
			exit(1);
		};

        to[n] = (u8) a | 0x80; 
		to[n+1] = (u8) a; 

		//printf("n=0x%08X i=0x%08X\n",n,i);
        //printf("\ta: 0x%08X\n",a);
		//printf("\tn: 0x%08X\n",to[n]);
		//printf("\tn+1: 0x%08X\n",to[n+1]);
	};
	to[n]=a;

	//printf("after cikl, n=0x%08X\n",n);
    //printf("after cikl, a=0x%08X\n",a);
	//printf("\n");

	//printf("0: 0x%08X\n",to[0]);
	//printf("1: 0x%08X\n",to[1]);
	//printf("2: 0x%08X\n",to[2]);
	//printf("3: 0x%08X\n",to[3]);
	//printf("4: 0x%08X\n",to[4]);
	//printf("5: 0x%08X\n",to[5]);


	if (n > limit) {
		printf("not enought buffer\n");
		exit(1);
	};

	for(i=0;i<=n;i++){
		buf[i]=to[i] & 0xff;
	};



    return n+1;
}



int decode41(char *data, int len, char *text){
		struct self_s self;
		int ret;
		u8 *pkt_my;
		u32 pkt_my_len;


		pkt_my=data;
		pkt_my_len=len;

		ret=unpack41_structure(pkt_my,pkt_my_len,(char *)&self);
		if (ret==-1) {
			printf("possible not all bytes decoded! (not found last 2 bytes of crc16)\n");
		};

		if (ret==-2){
			return 0;
		};

		print_structure(text,(char *)&self,1);		

		free_structure((char *)&self);


	return 0;
};
