// example of 42 usage
//

#include "skype_basics.h"
#include "skype_rc4.h"
#pragma warning(disable:4311 4312)

#define error debuglog

#define MAX_MEM		16384

static void errdump (const u8 * const mem, const u32 n)
{
	u32		i, j, m = (__min(n,MAX_MEM)+15)&~15;
	char	s[512], *z;
	
	for (i = 0, z = s, *s = '\0'; i < m; i++)
	{
		if ((i&15)==0) z += sprintf (z, "%04X:", i);
		if (i < n) z += sprintf (z, " %02X", mem[i]); else z += sprintf (z, "   ");
		if ((i&15)==15)
		{
			*z++ =0x20; *z++ ='|'; *z++ =0x20;
			for (j = 0; j < 16; j++) *z++ = (i-15+j >= n) ? 0x20 : (mem[i-15+j]<0x20)||(mem[i-15+j]>0x7E) ? '.' : mem[i-15+j];
			*z++ =0x20; *z++ ='|'; *z++ ='\n'; *z = '\0';
			error ("%s", z = s); *s = '\0';
		}
	}
	if (n >= MAX_MEM) error ("...\n");
	error ("\n");
}

static void dump_blob (const char *header, const u32 type, const u32 m, const u32 n)
{
	u32			i;
	char		*s, out[1024];
	
	switch (type)
	{
	case 0:	// 32-bit
		error ("%s: %02X %02X %02X %02X\n", header, m&0xFF, (m>>8)&0xFF, (m>>16)&0xFF, m>>24);
		break;
	case 1: // 64-bit
		error ("%s: %02X %02X %02X %02X %02X %02X %02X %02X\n", header, m&0xFF, (m>>8)&0xFF, (m>>16)&0xFF, m>>24, n&0xFF, (n>>8)&0xFF, (n>>16)&0xFF, n>>24);
		break;
	case 2:	// IP:port
		error ("%s: %u.%u.%u.%u:%u\n", header, m>>24, (m>>16)&0xFF, (m>>8)&0xFF, m&0xFF, n);
		break;
	case 3:	// ASCIIZ
		if (byte(m,n-1) != 0) __asm int 3;	// just in case
		error ("%s: \"%s\"\n", header, m);
		break;
	case 4:	// BINARY
		error ("%s: %d bytes\n", header, n);
		errdump ((void*)m, n);
		break;
	case 5:	// recursion, gotta handle it upstairs
		__asm int 3;
		break;
	case 6:	// 32-bit words
		s += sprintf (s = out, "%s: ", header);
		for (i = 0; i < n; i += 4) s += sprintf (s, "%02X %02X %02X %02X%s", dword(m,i)&0xFF, (dword(m,i)>>8)&0xFF, (dword(m,i)>>16)&0xFF, dword(m,i)>>24, (i+4<n)?", ":"");
		error ("%s\n", out);
		break;
	default:
		//__asm int 3;
        ;
	}
}



static void dump_41 (const u32 type, const u32 id, const u32 m, const u32 n)
{
	char		aid[256];
	
	switch (id)
	{
//	case 0x00:	report ("SuperNode");
//	case 0x01:	report ("Command");
//	case 0x05:	report ("My Password MD5");
//	case 0x09:	report ("My Credentials Expiry Time");
//	case 0x0D:	report ("Skype Version");
//	case 0x0E:	report ("Login/Key Time/ID?");
//	case 0x20:	report ("My Email");
//	case 0x21:	report ("My Public Key");
//	case 0x24:	report ("My Credentials");
//	case 0x31:	report ("Host ID");
//	case 0x33:	report ("Host IDs");
//	case 0x37:	report ("My Name");
	default:	
			sprintf (aid, "%02X-%02X", type, id);
			dump_blob(aid,type,m,n);
			break;

	}
}

/*
typedef struct _skype_thing
{
	u32				type, id, m, n;
} skype_thing;

typedef struct _skype_list
{
	struct _skype_list	*next;
	skype_thing			*thing;
	u32					allocated_things;
	u32					things;
} skype_list;
*/

static void dump_41_list (const skype_list *list)
{
	u32				i, l;
	
	if (!list) { error ("<empty>\n"); return; }
	if (!list->things || !list->thing) { error ("<empty>\n"); return; }
	debuglog ("{\n");
	for (i = 0, l = 0; i < list->things; i++)
	{
		if (list->thing[i].type == 5)
		{
			debuglog("%02X-%02X: ",list->thing[i].type, list->thing[i].id);
			dump_41_list ((skype_list *)list->thing[i].m);
			continue;
		}
		dump_41 (list->thing[i].type, list->thing[i].id, list->thing[i].m, list->thing[i].n);
	}
	debuglog ("}\n");
}



int main_unpack (u8 *indata, u32 inlen) {
	u32				list_size;
	u8				*blob_pos = indata;
	u32				packed_bytes = inlen;
	skype_list		new_list = {&new_list, 0, 0, 0};
	int				ret;
	int				myvar=0;
	int				i;

	// stack mess
	int				myvar1=1;
	int				myvar2=1;
	int				myvar3=1;
	int				myvar4=1;
	int				myvar5=1;
	int				myvar6=1;
	int				myvar7=1;
	int				myvar8=0;


	list_size = 0x5000;

	i=0;
	while ((packed_bytes>0) && (blob_pos[0]!=0x41)){ 			
		packed_bytes--;
		blob_pos++;
		i++;
	    if (i > inlen){
			debuglog("AES DECODING ERROR!!!\n");
			return -1;
		};
	};

	//if (i > 16){
    //if (i > inlen){
    if (i > 0x50){
		debuglog("AES DECODING ERROR!!!\n");
		return -1;
	};

	ret=unpack_4142 ((u32*)&new_list, &blob_pos, &packed_bytes, 0, 8, &list_size);


	dump_41_list (&new_list);
	error ("\n");

	
	return 0;
};



////////////////////
//
// unpack and get connid
//


static void dump_41_list_getdata1 (const skype_list *list, u8 *cred, u8 *rnd64bit, u32 *sess_id)
{
	u32				i, l;
	
	if (!list) { 
		return; 
	}
	if (!list->things || !list->thing) { 
		return; 
	}
	for (i = 0, l = 0; i < list->things; i++) {
		
		if (list->thing[i].type == 5) {
			dump_41_list_getdata1 ((skype_list *)list->thing[i].m, cred, rnd64bit, sess_id);
			continue;
		};


		debuglog("Type:0x%08X\n",list->thing[i].type);
		debuglog("Id:0x%08X\n",list->thing[i].id);
		debuglog("m:0x%08X\n",list->thing[i].m);
		debuglog("n:0x%08X\n",list->thing[i].n);
		debuglog("\n");

		if ((list->thing[i].type == 0) && (list->thing[i].id == 3)) {
			if (*sess_id==0){
				*sess_id=list->thing[i].m;
			};
		};

		if ((list->thing[i].type == 1) && (list->thing[i].id == 9)) {
			memcpy(rnd64bit,&list->thing[i].m,4);
			memcpy(rnd64bit+4,&list->thing[i].n,4);
		};

		if ((list->thing[i].type == 4) && (list->thing[i].id == 5)) {
			memcpy(cred,(char *)list->thing[i].m,0x188);
		};

	}
}



int main_unpack_getdata1 (u8 *indata, u32 inlen, u8 *cred, u8 *rnd64bit, u32 *sess_id) {
	u32				list_size;
	u8				*blob_pos = indata;
	skype_list		new_list = {&new_list, 0, 0, 0};
	u32				packed_bytes_len;
	int				ret;

	// stack mess
	int				myvar1=1;
	int				myvar2=1;
	int				myvar3=1;
	int				myvar4=1;
	int				myvar5=1;
	int				myvar6=1;
	int				myvar7=1;
	int				myvar8=0;


	packed_bytes_len=inlen;

	list_size = 0x5000;

	while ((packed_bytes_len>0) && (blob_pos[0]!=0x41)){
		packed_bytes_len--;
		blob_pos++;
	};


	ret=1;
	while( (packed_bytes_len>0) && (ret==1) ){
		
		ret=unpack_4142 ((u32*)&new_list, &blob_pos, &packed_bytes_len, 0, 8, &list_size);

		while ((packed_bytes_len>0) && (blob_pos[0]!=0x41)){
			packed_bytes_len--;
			blob_pos++;
		};

	};

	dump_41_list_getdata1 (&new_list, cred, rnd64bit, sess_id);
	
	return inlen-packed_bytes_len;
};


/////////////////////////////////////////////////////////


static void dump_41_list_getdata2 (const skype_list *list, u8 *nonce)
{
	u32				i, l;
	
	if (!list) { 
		return; 
	}
	if (!list->things || !list->thing) { 
		return; 
	}
	for (i = 0, l = 0; i < list->things; i++) {
		
		if (list->thing[i].type == 5) {
			dump_41_list_getdata2 ((skype_list *)list->thing[i].m, nonce);
			continue;
		};

		
		if ((list->thing[i].type == 4) && (list->thing[i].id == 6)) {
			memcpy(nonce,(char *)list->thing[i].m, 0x80);
		};

	}
}




int main_unpack_getdata2 (u8 *indata, u32 inlen, u8 *nonce) {
	u32				list_size;
	u8				*blob_pos = indata;
	skype_list		new_list = {&new_list, 0, 0, 0};
	u32				packed_bytes;
	int				ret;

	// stack mess
	int				myvar1=1;
	int				myvar2=1;
	int				myvar3=1;
	int				myvar4=1;
	int				myvar5=1;
	int				myvar6=1;
	int				myvar7=1;
	int				myvar8=0;


	packed_bytes=inlen;

	list_size = 0x5000;

	while ((packed_bytes>0) && (blob_pos[0]!=0x41)){
		packed_bytes--;
		blob_pos++;
	};


	ret=1;
	while( (packed_bytes>0) && (ret==1) ){
		
		ret=unpack_4142 ((u32*)&new_list, &blob_pos, &packed_bytes, 0, 8, &list_size);

		while ((packed_bytes>0) && (blob_pos[0]!=0x41)){
			packed_bytes--;
			blob_pos++;
		};

	};

	dump_41_list_getdata2 (&new_list, nonce);
	
	return inlen-packed_bytes;
};



/////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////


static int dump_41_list_getbuf (const skype_list *list, u8 *membuf, int *membuf_len, int type, int id) {
	u32				i, l;
	
	if (!list) { 
		return 0; 
	}
	if (!list->things || !list->thing) { 
		return 0; 
	}
	for (i = 0, l = 0; i < list->things; i++) {
		
		if (list->thing[i].type == 5) {
			dump_41_list_getbuf((skype_list *)list->thing[i].m, membuf, membuf_len, type, id);
			continue;
		};
		

		// list->thing[i].n -- buf size

		if ((list->thing[i].type == type) && (list->thing[i].id == id)) {
			memcpy(membuf,(char *)list->thing[i].m, list->thing[i].n);
			*membuf_len = list->thing[i].n;
			//debuglog("list->thing[i].n: %08X\n",list->thing[i].n);
			//debuglog("list->thing[i].m: %08X\n",list->thing[i].m);
			//debuglog("list->thing[i].type: %08X\n",list->thing[i].type);
			//debuglog("list->thing[i].id: %08X\n",list->thing[i].id);
			return 1;
		};

	}

	return 0;
}


int main_unpack_getbuf (u8 *indata, u32 inlen, u8 *membuf, int *membuf_len, int type, int id) {
	u32				list_size;
	u8				*blob_pos = indata;
	skype_list		new_list = {&new_list, 0, 0, 0};
	u32				packed_bytes;
	int				ret;

	// stack mess
	int				myvar1=1;
	int				myvar2=1;
	int				myvar3=1;
	int				myvar4=1;
	int				myvar5=1;
	int				myvar6=1;
	int				myvar7=1;
	int				myvar8=0;


	packed_bytes=inlen;

	list_size = 0x5000;

	while ((packed_bytes>0) && (blob_pos[0]!=0x41)){
		packed_bytes--;
		blob_pos++;
	};


	ret=1;
	while( (packed_bytes>0) && (ret==1) ){
		
		ret=unpack_4142((u32*)&new_list, &blob_pos, &packed_bytes, 0, 8, &list_size);

		while ((packed_bytes>0) && (blob_pos[0]!=0x41)){
			packed_bytes--;
			blob_pos++;
		};

	};

	dump_41_list_getbuf (&new_list, membuf, membuf_len, type, id);
	
	return 0;
};


/////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////


static int dump_41_list_getbuf_count (const skype_list *list, int *blobs_count, int type, int id) {
	u32				i, l;
	
	if (!list) { 
		return 0; 
	}
	if (!list->things || !list->thing) { 
		return 0; 
	}
	for (i = 0, l = 0; i < list->things; i++) {
		
		if (list->thing[i].type == 5) {
			dump_41_list_getbuf_count((skype_list *)list->thing[i].m, blobs_count, type, id);
			continue;
		};
		
		if ((list->thing[i].type == type) && (list->thing[i].id == id)) {
			(*blobs_count) = (*blobs_count) + 1;
			if (0) {
                debuglog("blobs_count: %08X\n",*blobs_count);
            };
			//debuglog("list->thing[i].n: %08X\n",*blobs_count);
			//debuglog("list->thing[i].m: %08X\n",list->thing[i].m);
			//debuglog("list->thing[i].type: %08X\n",list->thing[i].type);
			//debuglog("list->thing[i].id: %08X\n",list->thing[i].id);
		};

	}

	return 0;
}


int main_unpack_getbuf_count (u8 *indata, u32 inlen, int *blobs_count, int type, int id) {
	u32				list_size;
	u8				*blob_pos = indata;
	skype_list		new_list = {&new_list, 0, 0, 0};
	u32				packed_bytes;
	int				ret;

	// stack mess
	int				myvar1=1;
	int				myvar2=1;
	int				myvar3=1;
	int				myvar4=1;
	int				myvar5=1;
	int				myvar6=1;
	int				myvar7=1;
	int				myvar8=0;


	packed_bytes=inlen;

	list_size = 0x5000;

	while ((packed_bytes>0) && (blob_pos[0]!=0x41)){
		packed_bytes--;
		blob_pos++;
	};

	ret=1;
	while( (packed_bytes>0) && (ret==1) ){
		
		ret=unpack_4142((u32*)&new_list, &blob_pos, &packed_bytes, 0, 8, &list_size);

		while ((packed_bytes>0) && (blob_pos[0]!=0x41)){
			packed_bytes--;
			blob_pos++;
		};

	};

	dump_41_list_getbuf_count (&new_list, blobs_count, type, id);
	
	return 0;
};


/////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////


static int dump_41_list_getbuf_one (const skype_list *list, u8 *membuf, int *membuf_len, int *count, int index, int type, int id) {
	u32				i, l;
    int ret;
	
	if (!list) { 
		return 0; 
	}
	if (!list->things || !list->thing) { 
		return 0; 
	}

    ret = 0;

	for (i = 0, l = 0; i < list->things; i++) {
		
		if (list->thing[i].type == 5) {
			ret = dump_41_list_getbuf_one((skype_list *)list->thing[i].m, membuf, membuf_len, count, index, type, id);
            if (ret) {
                return ret;
            };
			continue;
		};
		
		if ((list->thing[i].type == type) && (list->thing[i].id == id)) {
			if (0){
                debuglog("Count: %d\n",*count);
                debuglog("Index: %d\n",index);
            };
            if (index==(*count)) {
    			memcpy(membuf,(char *)list->thing[i].m, list->thing[i].n);
    			*membuf_len = list->thing[i].n;
                return 1;
            };
            (*count) = (*count) + 1;
			//debuglog("list->thing[i].n: %08X\n",list->thing[i].n);
			//debuglog("list->thing[i].m: %08X\n",list->thing[i].m);
			//debuglog("list->thing[i].type: %08X\n",list->thing[i].type);
			//debuglog("list->thing[i].id: %08X\n",list->thing[i].id);
		};

	}

	return ret;
}


int main_unpack_getbuf_one (u8 *indata, u32 inlen, u8 *membuf, int *membuf_len, int index, int type, int id) {
	u32				list_size;
	u8				*blob_pos = indata;
	skype_list		new_list = {&new_list, 0, 0, 0};
	u32				packed_bytes;
	int				ret;
    int             count;

	// stack mess
	int				myvar1=1;
	int				myvar2=1;
	int				myvar3=1;
	int				myvar4=1;
	int				myvar5=1;
	int				myvar6=1;
	int				myvar7=1;
	int				myvar8=0;


	packed_bytes=inlen;

	list_size = 0x5000;

	while ((packed_bytes>0) && (blob_pos[0]!=0x41)){
		packed_bytes--;
		blob_pos++;
	};


	ret=1;
	while( (packed_bytes>0) && (ret==1) ){
		
		ret=unpack_4142((u32*)&new_list, &blob_pos, &packed_bytes, 0, 8, &list_size);

		while ((packed_bytes>0) && (blob_pos[0]!=0x41)){
			packed_bytes--;
			blob_pos++;
		};

	};

    count = 0;
	ret = dump_41_list_getbuf_one (&new_list, membuf, membuf_len, &count, index, type, id);
	
	return ret;
};



///////////////////////
///////////////////////
///////////////////////


//
// search for last value of object type 00
//
static int dump_41_list_getobj00_last (const skype_list *list, u32 *data_int, int type, int id) {
	u32				i, l;
	
	if (!list) { 
		return 0; 
	}
	if (!list->things || !list->thing) { 
		return 0; 
	}
	for (i = 0, l = 0; i < list->things; i++) {
		
		if (list->thing[i].type == 5) {
			dump_41_list_getobj00_last((skype_list *)list->thing[i].m, data_int, type, id);
			continue;
		};

		if ((list->thing[i].type == type) && (list->thing[i].id == id)) {
			//if (*data_int==0){
				*data_int=list->thing[i].m;
				//memcpy(data_int, &list->thing[i].m,4);
			//};
			//return 1;
		};

	}

	return 0;
}


//
// search for last value
//
int main_unpack_getobj00_last (u8 *indata, u32 inlen, u32 *data_int, int type, int id) {
	u32				list_size;
	u8				*blob_pos = indata;
	skype_list		new_list = {&new_list, 0, 0, 0};
	u32				packed_bytes;
	int				ret;

	// stack mess
	int				myvar1=1;
	int				myvar2=1;
	int				myvar3=1;
	int				myvar4=1;
	int				myvar5=1;
	int				myvar6=1;
	int				myvar7=1;
	int				myvar8=0;


	packed_bytes=inlen;

	list_size = 0x5000;

	while ((packed_bytes>0) && (blob_pos[0]!=0x41)){
		packed_bytes--;
		blob_pos++;
	};


	ret=1;
	while( (packed_bytes>0) && (ret==1) ){
		
		ret=unpack_4142 ((u32*)&new_list, &blob_pos, &packed_bytes, 0, 8, &list_size);

		while ((packed_bytes>0) && (blob_pos[0]!=0x41)){
			packed_bytes--;
			blob_pos++;
		};

	};

	dump_41_list_getobj00_last (&new_list, data_int, type, id);
	
	return 0;
};


///////////////////////
///////////////////////
///////////////////////


//
// search for first value of object type 00
//
static int dump_41_list_getobj00_first2(const skype_list *list, u32 *data_int, int type, int id) {
	u32				i, l;
	
	if (!list) { 
		return 0; 
	}
	if (!list->things || !list->thing) { 
		return 0; 
	}
	for (i = 0, l = 0; i < list->things; i++) {

		if ((list->thing[i].type == type) && (list->thing[i].id == id)) {
			*data_int=list->thing[i].m;
			return 1;
		};

	}

	return 0;
}


//
// search for first value of object type 00
//
static int dump_41_list_getobj00_first(const skype_list *list, u32 *data_int, int type, int id) {
	u32				i, l;
	
	if (!list) { 
		return 0; 
	}
	if (!list->things || !list->thing) { 
		return 0; 
	}
	for (i = 0, l = 0; i < list->things; i++) {
		
		if (list->thing[i].type == 5) {
			dump_41_list_getobj00_first2((skype_list *)list->thing[i].m, data_int, type, id);
			//continue;
            return 1;
		};

		if ((list->thing[i].type == type) && (list->thing[i].id == id)) {
			*data_int=list->thing[i].m;
			return 1;
		};

	}

	return 0;
}


//
// search for first value
//
int main_unpack_getobj00_first (u8 *indata, u32 inlen, u32 *data_int, int type, int id) {
	u32				list_size;
	u8				*blob_pos = indata;
	skype_list		new_list = {&new_list, 0, 0, 0};
	u32				packed_bytes;
	int				ret;

	// stack mess
	int				myvar1=1;
	int				myvar2=1;
	int				myvar3=1;
	int				myvar4=1;
	int				myvar5=1;
	int				myvar6=1;
	int				myvar7=1;
	int				myvar8=0;


	packed_bytes=inlen;

	list_size = 0x5000;

	while ((packed_bytes>0) && (blob_pos[0]!=0x41)){
		packed_bytes--;
		blob_pos++;
	};


	if (packed_bytes>0) {
		ret=unpack_4142 ((u32*)&new_list, &blob_pos, &packed_bytes, 0, 8, &list_size);
	};

	ret = dump_41_list_getobj00_first (&new_list, data_int, type, id);
	
	return ret;
};


///////////////////////
///////////////////////
///////////////////////


//
// unpack and get value of type 01
//


static int dump_41_list_getobj01 (const skype_list *list, u8 *data_64bit, int type, int id) {
	u32				i, l;
	
	if (!list) { 
		return 0; 
	}
	if (!list->things || !list->thing) { 
		return 0; 
	}
	for (i = 0, l = 0; i < list->things; i++) {
		
		if (list->thing[i].type == 5) {
			dump_41_list_getobj01((skype_list *)list->thing[i].m, data_64bit, type, id);
			continue;
		};

		if ((list->thing[i].type == type) && (list->thing[i].id == id)) {
			memcpy(data_64bit, &list->thing[i].m, 4);
			memcpy(data_64bit+4, &list->thing[i].n, 4);

			return 1;
		};

	}

	return 0;
}



int main_unpack_getobj01 (u8 *indata, u32 inlen, u8 *data_64bit, int type, int id) {
	u32				list_size;
	u8				*blob_pos = indata;
	skype_list		new_list = {&new_list, 0, 0, 0};
	u32				packed_bytes;
	int				ret;

	// stack mess
	int				myvar1=1;
	int				myvar2=1;
	int				myvar3=1;
	int				myvar4=1;
	int				myvar5=1;
	int				myvar6=1;
	int				myvar7=1;
	int				myvar8=0;


	packed_bytes=inlen;

	list_size = 0x5000;

	while ((packed_bytes>0) && (blob_pos[0]!=0x41)){
		packed_bytes--;
		blob_pos++;
	};


	ret=1;
	while( (packed_bytes>0) && (ret==1) ){
		
		ret=unpack_4142 ((u32*)&new_list, &blob_pos, &packed_bytes, 0, 8, &list_size);

		while ((packed_bytes>0) && (blob_pos[0]!=0x41)){
			packed_bytes--;
			blob_pos++;
		};

	};

	dump_41_list_getobj01 (&new_list, data_64bit, type, id);
	
	return 0;
};


/////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////


int main_unpack42 (u8 *indata, u32 inlen) {
    u32             list_size;
    u8              *blob_pos = indata;
    u32             packed_bytes = inlen;
    skype_list      new_list = {&new_list, 0, 0, 0};
    int             ret;
    int             myvar=0;
    int             i;

    // stack mess
    int             myvar1=1;
    int             myvar2=1;
    int             myvar3=1;
    int             myvar4=1;
    int             myvar5=1;
    int             myvar6=1;
    int             myvar7=1;
    int             myvar8=0;


    list_size = 0x5000;

    while ((packed_bytes>0) && (blob_pos[0]!=0x41 && blob_pos[0]!=0x42)){
        packed_bytes--;
        blob_pos++;
    };

    //if (i > 16){
    //if (i > inlen){
    /*
    if (i > 0x50){
        debuglog("AES DECODING ERROR!!!\n");
        return -1;
    };
    */

    ret=unpack_4142 ((u32*)&new_list, &blob_pos, &packed_bytes, 0, 8, &list_size);


    dump_41_list (&new_list);
    error ("\n");

    
    return 0;
};

/////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////

//
// pack
//
int main_pack_into (skype_list *list, u8 *outdata, u32 maxlen) {
    u32             list_size = 1;
    u32             packed_bytes;

    list_size = 0x50000;

    packed_bytes = pack_4142 ( (u32 *)list, outdata, 1, list_size);
    
    return packed_bytes;
};
