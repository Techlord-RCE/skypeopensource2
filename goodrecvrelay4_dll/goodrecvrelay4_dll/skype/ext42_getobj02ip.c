//
// Add on function for blob management
//

#include "skype_basics.h"
#include "skype_rc4.h"


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

        };
        count++;
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

        while ((packed_bytes>0) && (blob_pos[0]!=0x41)){
            packed_bytes--;
            blob_pos++;
        };
        count++;
    };
    
    return 0;
};


