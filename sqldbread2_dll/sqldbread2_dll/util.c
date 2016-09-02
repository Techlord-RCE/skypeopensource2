


//////////////////////
// Util             //
//////////////////////
int show_memory(char *mem, int len, char *text){
	int zz;
	int i;

	debuglog("%s\n",text);
	debuglog("Len: 0x%08X\n",len);

	zz=0;
	for(i=0;i<len;i++){
		debuglog("%02X ",mem[i] & 0xff);
		zz++;if (zz == 16) { zz=0; debuglog("\n ");};
	};
	debuglog("\n");

	return 0;
};


int show_memory_with_ascii(char *mem, int len, char *text){
	int zz;
	int i;
	int k;
	char b[16+1];
	int t;

	debuglog("%s\n",text);
	debuglog("Len: 0x%08X\n",len);

	zz=0;
	k=0;
	b[16]=0;
	for(i=0;i<len;i++){
		debuglog("%02X ",mem[i] & 0xff);
		t=mem[i] & 0xff;
		if ((t>=0x20) && (t<=0x7f)){
			memcpy(b+k,mem+i,1);
		}else{
			memcpy(b+k,"\x20",1);
		};
		zz++;
		k++;
		if (zz == 16) { 
			zz=0;
			k=0;
            debuglog(" ; %s",b);
			debuglog("\n");

		};
	};

    // last line
	if (zz != 16) {
        b[zz]=0x00;
        debuglog(" ; %s",b);
		debuglog("\n");

	};

	debuglog("\n");

	return 0;
};

