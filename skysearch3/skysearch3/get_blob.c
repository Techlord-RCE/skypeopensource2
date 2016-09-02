//
// parse returned data
//

#include <stdio.h>
#include <stdlib.h>

#include "short_types.h"


/*
{
05-06: {
02-03: 157.56.52.41:40001
02-03: 111.221.74.41:40002
02-03: 157.55.235.169:40001
02-03: 157.55.130.146:40001
02-03: 65.55.223.41:40001
00-00: F2 02 00 00
00-07: 05 00 00 00
}
}
*/

int get_02_03_blob(char *membuf, int membuf_len) {
	int ret;
    u32 ip;
    u32 port;
    u32 slot;
    int size;
    int i;
    int pktnum;
    FILE *fp;
    int total;

	printf("Looking for 02-03 (supernode ip:port) blob...\n");
	ret = main_unpack_checkblob(membuf, membuf_len, 0x02, 0x03);
	if (ret == 1) {
		printf("BLOB found!\n");

        fp=fopen("./_getnodes.txt","w");
        fclose(fp);

        fp=fopen("./_getnodes.txt","a");
        fprintf(fp,":: new dump ::\n");

        total=0;
   		pktnum = 0;
        while(main_unpack_getobj02slot(membuf, membuf_len, &slot, &size, 0x02, 0x03, pktnum)) {
            if (size <= 0) {
                printf("Some error occured when calculating the size of ip:port list, size = %d, 0x%08X\n", size, size);
                return -1;
            };
       		printf("\nSlot: #%d 0x%08X\n", slot, slot);
			fprintf(fp,"\nSlot: #%d 0x%08X\n", slot, slot);
            if (0) {
           		printf("size: %d\n", size);
            };
            for(i=0; i<size; i++) {
               	ret = main_unpack_getobj02ip(membuf, membuf_len, &ip, &port, 0x02, 0x03, pktnum, i);
    			if (ret) {
                    total++;
        			printf("%u.%u.%u.%u:%u\n", ip>>24, (ip>>16)&0xFF, (ip>>8)&0xFF, ip&0xFF, port);
        			fprintf(fp,"%u.%u.%u.%u:%u\n", ip>>24, (ip>>16)&0xFF, (ip>>8)&0xFF, ip&0xFF, port);
    			};
            };
            pktnum++;
        };

        printf("\nSaved %d nodes.\n",total);
        fprintf(fp, "\n:: %d nodes saved ::\n",total);
        fclose(fp);
	};

	return 0;
};


///
// get our public ip from supernode answer
//
int get_02_11_blob(char *membuf, int membuf_len, char *our_public_ip) {
	int ret;
    u32 ip;
    u32 port;
    int i;
    int pktnum;

	printf("Looking for 02-11 (supernode ip:port) blob...\n");
	ret = main_unpack_checkblob(membuf, membuf_len, 0x02, 0x11);
	if (ret == 1) {
		printf("BLOB found!\n");

   		pktnum = 0;
        i = 0;
       	ret = main_unpack_getobj02ip(membuf, membuf_len, &ip, &port, 0x02, 0x11, pktnum, i);
		if (ret) {
            sprintf(our_public_ip, "%u.%u.%u.%u", ip>>24, (ip>>16)&0xFF, (ip>>8)&0xFF, ip&0xFF);
            printf("%u.%u.%u.%u:%u\n", ip>>24, (ip>>16)&0xFF, (ip>>8)&0xFF, ip&0xFF, port);
            printf("our_public_ip: %s\n", our_public_ip);
        };

	};

    return ret;
};


//
// 04-0B signed cert blob
//
int get_04_0B_blob_seq(u8 *buf, int len, u8 *membuf, int *membuf_len, int pktnum, int next) {
	int ret;

    ret = main_unpack_getbuf_seq(buf, len, membuf, membuf_len, 0x04, 0x0B, pktnum, next);
	if (*membuf_len < 0) {
    	printf("unpack_getbuf size error\n");
		return -1;
	};

    if (ret) {
    	printf("BLOB found!\n");

    	printf("MEMBUF_LEN: %d bytes\n", *membuf_len);
    	show_memory(membuf, *membuf_len, "MEMBUF");
    };

	return ret;
};


//
// 00-01 error code check
//
int get_00_01_blob(u8 *buf, int buf_len, int *code){
	int ret;
	unsigned long data_int;

	printf("Looking for 00-01 blob...\n");
	ret = main_unpack_checkblob(buf, buf_len, 0x00, 0x01);
	if (ret == 1){
		printf("BLOB found!\n");
		main_unpack_getobj00(buf, buf_len, &data_int, 0x00, 0x01);
		printf("00-01: 0x%08X\n", data_int);
		*code = data_int;
	};

	return 0;
};
