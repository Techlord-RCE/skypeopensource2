// example of 42 usage
//

#include "skype_basics.h"
#include "skype_rc4.h"
#pragma warning(disable:4311 4312)

#define error printf

#define MAX_MEM     16384

static void errdump (const u8 * const mem, const u32 n)
{
    u32     i, j, m = (__min(n,MAX_MEM)+15)&~15;
    //char  s[512], *z;
    char    s[4096], *z;
    
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
    u32         i;
    char        *s, out[1024];
    
    switch (type)
    {
    case 0: // 32-bit
        error ("%s: %02X %02X %02X %02X\n", header, m&0xFF, (m>>8)&0xFF, (m>>16)&0xFF, m>>24);
        break;
    case 1: // 64-bit
        error ("%s: %02X %02X %02X %02X %02X %02X %02X %02X\n", header, m&0xFF, (m>>8)&0xFF, (m>>16)&0xFF, m>>24, n&0xFF, (n>>8)&0xFF, (n>>16)&0xFF, n>>24);
        break;
    case 2: // IP:port
        error ("%s: %u.%u.%u.%u:%u\n", header, m>>24, (m>>16)&0xFF, (m>>8)&0xFF, m&0xFF, n);
        break;
    case 3: // ASCIIZ
        if ((m==0) && (n==0)) {
            error ("41_ERROR3: 0x%08X 0x%08X\n", m, n);
            break;
        }
        if (byte(m,n-1) != 0) { 
            //__asm int 3;  // just in case
            error ("41_ERROR2: 0x%08X 0x%08X\n", m, n);
        };
        error ("%s: \"%s\"\n", header, m);
        break;
    case 4: // BINARY
        error ("%s: %d bytes\n", header, n);
        if (m==0) {
            error ("41_ERROR4: 0x%08X 0x%08X\n", m, n);
            break;
        }
        errdump ((void*)m, n);
        break;
    case 5: // recursion, gotta handle it upstairs
        __asm int 3;
        break;
    case 6: // 32-bit words
        s += sprintf (s = out, "%s: ", header);
        for (i = 0; i < n; i += 4) s += sprintf (s, "%02X %02X %02X %02X%s", dword(m,i)&0xFF, (dword(m,i)>>8)&0xFF, (dword(m,i)>>16)&0xFF, dword(m,i)>>24, (i+4<n)?", ":"");
        error ("%s\n", out);
        break;
    default:
        error ("41_ERROR1: %d 0x%08X\n", type, type);
        //__asm int 3;
    }
}



static void dump_41 (const u32 type, const u32 id, const u32 m, const u32 n)
{
    char        aid[256];
    
    switch (id)
    {
//  case 0x00:  report ("SuperNode");
//  case 0x01:  report ("Command");
//  case 0x05:  report ("My Password MD5");
//  case 0x09:  report ("My Credentials Expiry Time");
//  case 0x0D:  report ("Skype Version");
//  case 0x0E:  report ("Login/Key Time/ID?");
//  case 0x20:  report ("My Email");
//  case 0x21:  report ("My Public Key");
//  case 0x24:  report ("My Credentials");
//  case 0x31:  report ("Host ID");
//  case 0x33:  report ("Host IDs");
//  case 0x37:  report ("My Name");
    default:    
            sprintf (aid, "%02X-%02X", type, id);
            dump_blob(aid,type,m,n);
            break;

    }
}

/*
typedef struct _skype_thing
{
    u32             type, id, m, n;
} skype_thing;

typedef struct _skype_list
{
    struct _skype_list  *next;
    skype_thing         *thing;
    u32                 allocated_things;
    u32                 things;
} skype_list;
*/

static void dump_41_list (const skype_list *list)
{
    u32             i, l;
    
    if (!list) { error ("<empty>\n"); return; }
    if (!list->things || !list->thing) { error ("<empty>\n"); return; }
    printf ("{\n");
    for (i = 0, l = 0; i < list->things; i++)
    {
        if (list->thing[i].type == 5)
        {
            printf("%02X-%02X: ",list->thing[i].type, list->thing[i].id);
            dump_41_list ((skype_list *)list->thing[i].m);
            continue;
        }
        dump_41 (list->thing[i].type, list->thing[i].id, list->thing[i].m, list->thing[i].n);
    }
    printf ("}\n");
}



int main_unpack (u8 *indata, u32 inlen) {
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

    i=0;
    while ((packed_bytes>0) && (blob_pos[0]!=0x41)){            
        packed_bytes--;
        blob_pos++;
        i++;
        if (i > inlen){
            printf("AES DECODING ERROR!!!\n");
            show_memory(indata, inlen, "Error on:");
            return -1;
        };
    };

    //if (i > 16){
    //if (i > inlen){
    if (i > 0x50){
        printf("AES DECODING ERROR!!!\n");
        show_memory(indata, inlen, "Error on:");
        return -1;
    };

    ret=unpack_4142 ((u32*)&new_list, &blob_pos, &packed_bytes, 0, 8, &list_size);


    dump_41_list (&new_list);
    error ("\n");

    
    return 0;
};


int main_unpack_all (u8 *indata, u32 inlen) {
    u32             list_size;
    u8              *blob_pos = indata;
    skype_list      new_list = {&new_list, 0, 0, 0};
    u32             packed_bytes;
    int             ret;

    // stack mess
    int             myvar1=1;
    int             myvar2=1;
    int             myvar3=1;
    int             myvar4=1;
    int             myvar5=1;
    int             myvar6=1;
    int             myvar7=1;
    int             myvar8=0;


    packed_bytes=inlen;

    list_size = 0x5000;

    while ((packed_bytes>0) && (blob_pos[0]!=0x41)){
        packed_bytes--;
        blob_pos++;
    };


    ret=1;
    while( (packed_bytes>0) && (ret==1) ){
        
        ret=unpack_4142 ((u32*)&new_list, &blob_pos, &packed_bytes, 0, 8, &list_size);
    
        dump_41_list (&new_list);
        error ("\n");

        memset(&new_list, 0, sizeof(new_list));

        //new_list.allocated_things = &new_list
        //new_list.next = 0;
        // 0, 0;

        while ((packed_bytes>0) && (blob_pos[0]!=0x41)){
            packed_bytes--;
            blob_pos++;
        };

    };

    
    return inlen-packed_bytes;
};


////////////////////
//
// unpack and get connid
//


static void dump_41_list_getdata1 (const skype_list *list, u8 *cred, u8 *rnd64bit, u32 *sess_id)
{
    u32             i, l;
    
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


        printf("Type:0x%08X\n",list->thing[i].type);
        printf("Id:0x%08X\n",list->thing[i].id);
        printf("m:0x%08X\n",list->thing[i].m);
        printf("n:0x%08X\n",list->thing[i].n);
        printf("\n");

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
    u32             list_size;
    u8              *blob_pos = indata;
    skype_list      new_list = {&new_list, 0, 0, 0};
    u32             packed_bytes_len;
    int             ret;

    // stack mess
    int             myvar1=1;
    int             myvar2=1;
    int             myvar3=1;
    int             myvar4=1;
    int             myvar5=1;
    int             myvar6=1;
    int             myvar7=1;
    int             myvar8=0;


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
    u32             i, l;
    
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
    u32             list_size;
    u8              *blob_pos = indata;
    skype_list      new_list = {&new_list, 0, 0, 0};
    u32             packed_bytes;
    int             ret;

    // stack mess
    int             myvar1=1;
    int             myvar2=1;
    int             myvar3=1;
    int             myvar4=1;
    int             myvar5=1;
    int             myvar6=1;
    int             myvar7=1;
    int             myvar8=0;


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
    u32             i, l;
    
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
            //printf("list->thing[i].n: %08X\n",list->thing[i].n);
            //printf("list->thing[i].m: %08X\n",list->thing[i].m);
            //printf("list->thing[i].type: %08X\n",list->thing[i].type);
            //printf("list->thing[i].id: %08X\n",list->thing[i].id);
            return 1;
        };

    }

    return 0;
}




int main_unpack_getbuf (u8 *indata, u32 inlen, u8 *membuf, int *membuf_len, int type, int id) {
    u32             list_size;
    u8              *blob_pos = indata;
    skype_list      new_list = {&new_list, 0, 0, 0};
    u32             packed_bytes;
    int             ret;

    // stack mess
    int             myvar1=1;
    int             myvar2=1;
    int             myvar3=1;
    int             myvar4=1;
    int             myvar5=1;
    int             myvar6=1;
    int             myvar7=1;
    int             myvar8=0;


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

static int dump_41_list_getbuf_seq(const skype_list *list, u8 *membuf, int *membuf_len, int type, int id, int next, int *count) {
    u32             i, l;
    int             ret;
    
    if (!list) { 
        return 0; 
    }
    if (!list->things || !list->thing) { 
        return 0; 
    }
    ret = 0; 
    for (i = 0, l = 0; i < list->things; i++) {
        
        if (list->thing[i].type == 5) {
            if (0) {
                printf("type5 count (bef): %d\n", *count);
            };
            ret = dump_41_list_getbuf_seq((skype_list *)list->thing[i].m, membuf, membuf_len, type, id, next, count);
            if (0) {
                printf("type5 count (aft): %d\n", *count);
            };
            // no need to check more
            if (ret) {
                return 1;
            };
            continue;
        };

        if ((list->thing[i].type == type) && (list->thing[i].id == id)) {
    
            if (0) {
                printf("list->thing[i].type: %08X\n",list->thing[i].type);
                printf("list->thing[i].id: %08X\n",list->thing[i].id);

                printf("count: %d\n", *count);
                printf("next: %d\n", next);
            };

            if (*count == next) {
                if (list->thing[i].m==0) {
                    printf("Some strange error in 41 unpack\n");
                    return 0;
                };
                memcpy(membuf,(char *)list->thing[i].m, list->thing[i].n);
                *membuf_len = list->thing[i].n;
                return 1;
            };

            *count = *count + 1;

            if (0) {
                printf("aft count: %d\n", *count);
            };

            //printf("list->thing[i].n: %08X\n",list->thing[i].n);
            //printf("list->thing[i].m: %08X\n",list->thing[i].m);
            //printf("list->thing[i].type: %08X\n",list->thing[i].type);
            //printf("list->thing[i].id: %08X\n",list->thing[i].id);
        };

    };

    return ret;
}


int main_unpack_getbuf_seq (u8 *indata, u32 inlen, u8 *membuf, int *membuf_len, int type, int id, int pktnum, int next) {
    u32             list_size;
    u8              *blob_pos = indata;
    skype_list      new_list = {&new_list, 0, 0, 0};
    u32             packed_bytes;
    int             ret;

    // stack mess
    int             myvar1=1;
    int             myvar2=1;
    int             myvar3=1;
    int             myvar4=1;
    int             myvar5=1;
    int             myvar6=1;
    int             myvar7=1;
    int             myvar8=0;
    int             count;
    int             count2;

    packed_bytes=inlen;

    list_size = 0x5000;

    while ((packed_bytes>0) && (blob_pos[0]!=0x41)){
        packed_bytes--;
        blob_pos++;
    };

    count2 = 0;
    ret=1;
    while( (packed_bytes>0) && (ret==1) ){
        
        if (0) {
            printf("next: %d\n", next);
            printf("\n");
            printf("count2: %d\n", count2);
            printf("pktnum: %d\n", pktnum);
        };

        memset(&new_list, 0, sizeof(new_list));
        unpack_4142((u32*)&new_list, &blob_pos, &packed_bytes, 0, 8, &list_size);

        if (count2 == pktnum) {
            count = 0;
            ret = dump_41_list_getbuf_seq (&new_list, membuf, membuf_len, type, id, next, &count);
            if (0) {
                printf("-- ret: %d\n", ret);
            };
            return ret;
        };
        count2++;

        while ((packed_bytes>0) && (blob_pos[0]!=0x41)){
            packed_bytes--;
            blob_pos++;
        };

    };
    
    return 0;
};


/////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////


static int dump_41_list_checkblob (const skype_list *list, int type, int id) {
    u32 i, l;
    int ret;
    
    if (!list) { 
        return 0; 
    }
    if (!list->things || !list->thing) { 
        return 0; 
    }
    for (i = 0, l = 0; i < list->things; i++) {
        
        if (list->thing[i].type == 5) {
            ret = dump_41_list_checkblob((skype_list *)list->thing[i].m, type, id);
            if (ret==1){
                return 1;
            }

            continue;
        };

        if ((list->thing[i].type == type) && (list->thing[i].id == id)) {
            return 1;
        };

    }


    return 0;
}




int main_unpack_checkblob (u8 *indata, u32 inlen, int type, int id) {
    u32             list_size;
    u8              *blob_pos = indata;
    skype_list      new_list = {&new_list, 0, 0, 0};
    u32             packed_bytes;
    int             ret;

    // stack mess
    int             myvar1=1;
    int             myvar2=1;
    int             myvar3=1;
    int             myvar4=1;
    int             myvar5=1;
    int             myvar6=1;
    int             myvar7=1;
    int             myvar8=0;


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

    ret = dump_41_list_checkblob(&new_list, type, id);
    
    return ret;
};



///////////////////////
///////////////////////
///////////////////////

//
// unpack and get value of type 00
//


static int dump_41_list_getobj00 (const skype_list *list, u32 *data_int, int type, int id) {
    u32             i, l;
    
    if (!list) { 
        return 0; 
    }
    if (!list->things || !list->thing) { 
        return 0; 
    }
    for (i = 0, l = 0; i < list->things; i++) {
        
        if (list->thing[i].type == 5) {
            dump_41_list_getobj00((skype_list *)list->thing[i].m, data_int, type, id);
            continue;
        };

        if ((list->thing[i].type == type) && (list->thing[i].id == id)) {
            //if (*data_int==0){
                *data_int=list->thing[i].m;
                //memcpy(data_int, &list->thing[i].m,4);
            //};
            return 1;
        };

    }

    return 0;
}



int main_unpack_getobj00 (u8 *indata, u32 inlen, u32 *data_int, int type, int id) {
    u32             list_size;
    u8              *blob_pos = indata;
    skype_list      new_list = {&new_list, 0, 0, 0};
    u32             packed_bytes;
    int             ret;

    // stack mess
    int             myvar1=1;
    int             myvar2=1;
    int             myvar3=1;
    int             myvar4=1;
    int             myvar5=1;
    int             myvar6=1;
    int             myvar7=1;
    int             myvar8=0;


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

    dump_41_list_getobj00 (&new_list, data_int, type, id);
    
    return 0;
};



///////////////////////
///////////////////////
///////////////////////

//
// unpack and get value of type 01
//


static int dump_41_list_getobj01 (const skype_list *list, u8 *data_64bit, int type, int id) {
    u32             i, l;
    
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
    u32             list_size;
    u8              *blob_pos = indata;
    skype_list      new_list = {&new_list, 0, 0, 0};
    u32             packed_bytes;
    int             ret;

    // stack mess
    int             myvar1=1;
    int             myvar2=1;
    int             myvar3=1;
    int             myvar4=1;
    int             myvar5=1;
    int             myvar6=1;
    int             myvar7=1;
    int             myvar8=0;


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


///////////////////////
///////////////////////
///////////////////////

//
// unpack and get value of type 02
//

static int dump_41_list_getobj02slot (const skype_list *list, u32  *slot, int *size, int type, int id) {
    u32             i, l;
    
    if (!list) { 
        return 0; 
    }
    if (!list->things || !list->thing) { 
        return 0; 
    }
    for (i = 0, l = 0; i < list->things; i++) {
        
        if (list->thing[i].type == 5) {
            dump_41_list_getobj02slot((skype_list *)list->thing[i].m, slot, size, type, id);
            continue;
        };

        if ((list->thing[i].type == 00) && (list->thing[i].id == 00)) {
                memcpy(slot, &list->thing[i].m, 4);
        };
        if ((list->thing[i].type == type) && (list->thing[i].id == id)) {
            if (0) {
                printf("i = %d\n", i);
                printf("size = %d\n", *size);
            };
            *size = *size + 1;
        };
    }

    return 1;
}



int main_unpack_getobj02slot (u8 *indata, u32 inlen, u32 *slot, int *size, int type, int id, int pktnum) {
    u32             list_size;
    u8              *blob_pos = indata;
    skype_list      new_list = {&new_list, 0, 0, 0};
    u32             packed_bytes;
    int             ret;
    int             count;

    // stack mess
    int             myvar1=1;
    int             myvar2=1;
    int             myvar3=1;
    int             myvar4=1;
    int             myvar5=1;
    int             myvar6=1;
    int             myvar7=1;
    int             myvar8=0;


    packed_bytes=inlen;

    list_size = 0x5000;

    while ((packed_bytes>0) && (blob_pos[0]!=0x41)){
        packed_bytes--;
        blob_pos++;
    };


    ret=1;
    count = 0;
    while( (packed_bytes>0) && (ret==1) ){

        if (0) {
            printf("count2: %d\n", count);
            printf("pktnum: %d\n", pktnum);
        };

        memset(&new_list, 0, sizeof(new_list));
        unpack_4142 ((u32*)&new_list, &blob_pos, &packed_bytes, 0, 8, &list_size);

        if (count == pktnum) {
            *size = 0;
            *slot = 0;
            ret = dump_41_list_getobj02slot (&new_list, slot, size, type, id);
            if (0) {
                printf("-- ret: %d\n", ret);
            };
            return ret;
        };

        while ((packed_bytes>0) && (blob_pos[0]!=0x41)){
            packed_bytes--;
            blob_pos++;
        };
        count++;
    };
    
    return 0;
};


///////////////////////
///////////////////////
///////////////////////

//
// unpack and get value of type 02
//

static int dump_41_list_getobj02ip (const skype_list *list, u32 *ip, u32 *port, int type, int id, int next) {
    u32             i, l;
    u32             count;
    int             ret;

    if (!list) { 
        return 0; 
    }
    if (!list->things || !list->thing) { 
        return 0; 
    }
    count = 0;
    ret = 0; 
    for (i = 0, l = 0; i < list->things; i++) {
        
        if (list->thing[i].type == 5) {
            ret = dump_41_list_getobj02ip((skype_list *)list->thing[i].m, ip, port, type, id, next);
            continue;
        };

        if ((list->thing[i].type == type) && (list->thing[i].id == id)) {
            if (0) {
                printf("count: %d\n", count);
                printf("next: %d\n", next);
            };
            if (count == next) {
                memcpy(ip, &list->thing[i].m, 4);
                memcpy(port, &list->thing[i].n, 4);
                return 1;
            };
            count++;
        };
        //count++;
    }

    return ret;
}



int main_unpack_getobj02ip (u8 *indata, u32 inlen, u32 *ip, u32 *port, int type, int id, int pktnum, int next) {
    u32             list_size;
    u8              *blob_pos = indata;
    skype_list      new_list = {&new_list, 0, 0, 0};
    u32             packed_bytes;
    int             ret;
    int             count;

    // stack mess
    int             myvar1=1;
    int             myvar2=1;
    int             myvar3=1;
    int             myvar4=1;
    int             myvar5=1;
    int             myvar6=1;
    int             myvar7=1;
    int             myvar8=0;


    packed_bytes=inlen;

    list_size = 0x5000;

    while ((packed_bytes>0) && (blob_pos[0]!=0x41)){
        packed_bytes--;
        blob_pos++;
    };


    ret=1;
    count = 0;
    while( (packed_bytes>0) && (ret==1) ){

        if (0) {
            printf("count2: %d\n", count);
            printf("pktnum: %d\n", pktnum);
        };

        memset(&new_list, 0, sizeof(new_list));
        unpack_4142 ((u32*)&new_list, &blob_pos, &packed_bytes, 0, 8, &list_size);

        if (count == pktnum) {
            *ip = 0;
            *port = 0;
            ret = dump_41_list_getobj02ip (&new_list, ip, port, type, id, next);
            if (0) {
                printf("-- ret: %d\n", ret);
            };
            return ret;
        };
        count++;

        while ((packed_bytes>0) && (blob_pos[0]!=0x41)){
            packed_bytes--;
            blob_pos++;
        };
    };
    
    return 0;
};


/////////////////////////////////////////////////
////////               new              /////////
/////////////////////////////////////////////////

//
// unpack all
//
int main_unpack_profile (u8 *indata, u32 inlen) {
    u32             list_size = 0;
    u8              *blob_pos = indata;
    skype_list      new_list = {&new_list, 0, 0, 0};
    u32             packed_bytes;
    int             ret;
    int             isPack42;

    packed_bytes=inlen;

    list_size = 0x50000;

    isPack42 = 1;

    while ((packed_bytes>0) && (blob_pos[0]!=0x42 && blob_pos[0]!=0x41)){
        packed_bytes--;
        blob_pos++;
    };


    ret=1;
    while( (packed_bytes>0) && (ret==1) ){
        
        ret=unpack_4142 ((u32*)&new_list, &blob_pos, &packed_bytes, &isPack42, 8, &list_size);

        while ((packed_bytes>0) && (blob_pos[0]!=0x42 && blob_pos[0]!=0x41)){
            packed_bytes--;
            blob_pos++;
        };

    };

    dump_41_list (&new_list);
    //error("\n");

    
    return 0;
};


int main_unpack42 (u8 *indata, u32 inlen) {
    u32             list_size = 0;
    u8              *blob_pos = indata;
    skype_list      new_list = {&new_list, 0, 0, 0};
    u32             packed_bytes;
    int             ret;
    int             isPack42;

    packed_bytes=inlen;

    list_size = 0x50000;

    isPack42 = 1;

    while ((packed_bytes>0) && (blob_pos[0]!=0x42)){            
        packed_bytes--;
        blob_pos++;
    };


    ret=1;
    while( (packed_bytes>0) && (ret==1) ){
        
        ret=unpack_4142 ((u32*)&new_list, &blob_pos, &packed_bytes, &isPack42, 8, &list_size);
        dump_41_list (&new_list);

        memset(&new_list, 0, sizeof(new_list));
    
        while ((packed_bytes>0) && (blob_pos[0]!=0x42)){            
            packed_bytes--;
            blob_pos++;
        };

    };

    //dump_41_list (&new_list);
    //error("\n");

    
    return 0;
};


//
// unpack exactly
//
int main_unpack_once (u8 *indata, u32 inlen) {
    u32             list_size = 0;
    u8              *blob_pos = indata;
    skype_list      new_list = {&new_list, 0, 0, 0};
    u32             packed_bytes;
    int             ret;

    packed_bytes=inlen;

    list_size = 0x50000;

    ret=unpack_4142 ((u32*)&new_list, &blob_pos, &packed_bytes, 0, 8, &list_size);

    dump_41_list (&new_list);
    
    return inlen-packed_bytes;
};



/*
// poryadok byte perevernut
skype_thing         mythings[] =
{
    {0, 0x01, 0x00000003, 0},
    {1, 0x0D, 0xD6BA8CD9, 0x9205E2CD},
    {0, 0x10, 0xA59A, 0},
};
*/

//
// pack
//
int main_pack (skype_thing *mythings, int mythings_len, u8 *outdata, u32 maxlen) {
    u32             list_size = 0;
    skype_list      list = {&list, mythings, mythings_len, mythings_len};
    u32             packed_bytes;


    list_size = 0x50000;

    packed_bytes = pack_4142 ( (u32 *)&list, outdata, 1, list_size);
    
    return packed_bytes;
};



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


////////////////////
//
// unpack and get info
//


static void dump_41_list_getip (const skype_list *list, u8 *ipinfo, u32 *ipinfo_len)
{
    u32             i, l;
    
    if (!list) { error ("<empty>\n"); return; }
    if (!list->things || !list->thing) { error ("<empty>\n"); return; }
    for (i = 0, l = 0; i < list->things; i++) {
        
        if (list->thing[i].type == 5) {
            error ("05-%02X: {\n", list->thing[i].id);
            dump_41_list_getip ((skype_list *)list->thing[i].m, ipinfo, ipinfo_len);
            error ("05-%02X: }\n", list->thing[i].id);
            continue;
        };

        //dump_41 (list->thing[i].type, list->thing[i].id, list->thing[i].m, list->thing[i].n);

        if ((list->thing[i].type == 4) && (list->thing[i].id == 3)) {
            memcpy(ipinfo, (u8 *)list->thing[i].m, list->thing[i].n);
            *ipinfo_len=list->thing[i].n;
        };

    }
}



int main_unpack_get (u8 *indata, u32 inlen, u8 *ipinfo, u32 *ipinfo_len) {
    u32             list_size = 0;
    u8              *blob_pos = indata;
    skype_list      new_list = {&new_list, 0, 0, 0};
    u32             packed_bytes;
    int             ret;

    packed_bytes=inlen;


    list_size = 0x50000;

    while ((packed_bytes>0) && (blob_pos[0]!=0x42 && blob_pos[0]!=0x41)){
        packed_bytes--;
        blob_pos++;
    };


    ret=1;
    while( (packed_bytes>0) && (ret==1) ){
        
        ret=unpack_4142 ((u32*)&new_list, &blob_pos, &packed_bytes, 0, 8, &list_size);

        while ((packed_bytes>0) && (blob_pos[0]!=0x42 && blob_pos[0]!=0x41)){
            packed_bytes--;
            blob_pos++;
        };

    };

    dump_41_list_getip (&new_list, ipinfo, ipinfo_len);
    
    return inlen-packed_bytes;
};


