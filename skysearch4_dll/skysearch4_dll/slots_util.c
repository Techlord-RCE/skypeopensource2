//
// file for slots utilities
//

#include <stdio.h>

#include "short_types.h"

#include "slots_util.h"

extern struct _slots slots[2048];


int load_slots_file(){
	FILE *fp;
	char line[8192];
	int file_ret;
	char *ptr;
	u32 slotid=0;

	fp=fopen("./_getnodes.txt","r");
	if (fp==NULL){
		printf("file not found\n");
		return -1;
	};
	

	do {
		line[0]=0;
		file_ret=fscanf(fp,"%s\n",&line);
		if (strlen(line)!=0){
			//printf("line: %s\n",line);
			if (strstr(line,"::")!=NULL){
				continue;
			};
			if (strstr(line,"Slot:")!=NULL){
				continue;
			};
			if (strstr(line,"0x")!=NULL){
				sscanf(line,"%x",&slotid);
				//printf("slotid: 0x%08X\n",slotid);
				slots[slotid].snodes_len=0;
				continue;
			};
			ptr=strchr(line,':');
			if (ptr!=NULL) {		
				ptr[0]=0;		
				slots[slotid].snodes[slots[slotid].snodes_len].ip=malloc(256);
				slots[slotid].snodes[slots[slotid].snodes_len].port=malloc(256);
				strncpy(slots[slotid].snodes[slots[slotid].snodes_len].ip,line,256);
				strncpy(slots[slotid].snodes[slots[slotid].snodes_len].port,ptr+1,256);				
				//printf("ip: %s port: %s\n",snodes_file->ip,snodes_file->port);
				slots[slotid].snodes_len++;
				if (slots[slotid].snodes_len > SNODES_MAX){
					printf("buf limit exceed\n");
					return -1;
				};
			};
		};
	}while(file_ret!=EOF);


	fclose(fp);


	return 0;
};

