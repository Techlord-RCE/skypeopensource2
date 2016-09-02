// example of 42 usage
//

#include "skype_basics.h"
#include "skype_rc4.h"

#pragma warning(disable:4311 4312)

#define MAX_MEM		16384

int errdump_log (u8 *mem, u32 n, char *str, int *slen) {
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
		    (*slen)+=sprintf(str+(*slen),"%s", z = s); *s = '\0';
		}
	}
	if (n >= MAX_MEM) { 
        (*slen)+=sprintf(str+(*slen),"...\n");
    };                       

	(*slen)+=sprintf(str+(*slen),"\n");

    return 0;
}

int dump_blob_log (char *header, u32 type, u32 m, u32 n, char *str, int *slen) {
	u32			i;
	char		*s, out[1024];
	
	switch (type)
	{
	case 0:	// 32-bit
		(*slen)+=sprintf(str+(*slen),"%s: %02X %02X %02X %02X\n", header, m&0xFF, (m>>8)&0xFF, (m>>16)&0xFF, m>>24);
		break;
	case 1: // 64-bit
		(*slen)+=sprintf(str+(*slen),"%s: %02X %02X %02X %02X %02X %02X %02X %02X\n", header, m&0xFF, (m>>8)&0xFF, (m>>16)&0xFF, m>>24, n&0xFF, (n>>8)&0xFF, (n>>16)&0xFF, n>>24);
		break;
	case 2:	// IP:port
		(*slen)+=sprintf(str+(*slen),"%s: %u.%u.%u.%u:%u\n", header, m>>24, (m>>16)&0xFF, (m>>8)&0xFF, m&0xFF, n);
		break;
	case 3:	// ASCIIZ
		if (byte(m,n-1) != 0) __asm int 3;	// just in case
		(*slen)+=sprintf(str+(*slen),"%s: \"%s\"\n", header, m);
		break;
	case 4:	// BINARY
		(*slen)+=sprintf(str+(*slen),"%s: %d bytes\n", header, n);
	    errdump_log ((void*)m, n, str, slen);
		break;
	case 5:	// recursion, gotta handle it upstairs
		__asm int 3;
		break;
	case 6:	// 32-bit words
		s += sprintf (s = out, "%s: ", header);
		for (i = 0; i < n; i += 4) s += sprintf (s, "%02X %02X %02X %02X%s", dword(m,i)&0xFF, (dword(m,i)>>8)&0xFF, (dword(m,i)>>16)&0xFF, dword(m,i)>>24, (i+4<n)?", ":"");
		(*slen)+=sprintf(str+(*slen),"%s\n", out);
		break;
	default:
		//__asm int 3;
        ;
	}

    return 0;
}


int dump_41_log (u32 type, u32 id, u32 m, u32 n, char *str, int *str_len) {
	char		aid[256];
    int slen = *str_len;
	
	sprintf(aid, "%02X-%02X", type, id);
    dump_blob_log(aid, type, m, n, str, str_len);

    return 0;
}


int dump_41_list_log (skype_list *list, char *str, int *slen) {
	u32				i, l;

	if (!list) { slen+=sprintf(str+(*slen), "<empty>\n"); return; }
	if (!list->things || !list->thing) { (*slen)+=sprintf(str+(*slen),"<empty>\n"); return; }
	(*slen)+=sprintf(str+(*slen),"{\n");
	for (i = 0, l = 0; i < list->things; i++)
	{
		if (list->thing[i].type == 5)
		{
			(*slen)+=sprintf(str+(*slen),"%02X-%02X: ",list->thing[i].type, list->thing[i].id);
			dump_41_list_log((skype_list *)list->thing[i].m, str, slen);
			continue;
		}
		dump_41_log(list->thing[i].type, list->thing[i].id, list->thing[i].m, list->thing[i].n, str, slen);
	}
	(*slen)+=sprintf(str+(*slen),"}\n");

    return 0;
}


int main_unpack_log(u8 *indata, u32 inlen, char *str, int *str_len) {
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
			debuglog("AES DECODING debuglog!!!\n");
			return -1;
		};
	};

	//if (i > 16){
    //if (i > inlen){
    if (i > 0x50){
		debuglog("AES DECODING debuglog!!!\n");
		return -1;
	};

	ret=unpack_4142((u32*)&new_list, &blob_pos, &packed_bytes, 0, 8, &list_size);

	dump_41_list_log(&new_list, str, str_len);
	
	return 0;
};
