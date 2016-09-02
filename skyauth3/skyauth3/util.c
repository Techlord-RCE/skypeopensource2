/*  
*
* Utils
*
* little help tools
*
*
*/

#include <stdio.h>
#include <stdlib.h>

// for uint
#include "short_types.h"


int encode_to_7bit(char *buf, uint word, int limit);

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
