//
// Add on function for blob management
//

#include "skype_basics.h"
#include "skype_rc4.h"


///////////////////////
///////////////////////
///////////////////////

//
// unpack and get value of type 00
//


static int dump_41_list_getobj00 (const skype_list *list, u32 *data_int, int type, int id) {
    u32             i, l;
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
            ret = dump_41_list_getobj00((skype_list *)list->thing[i].m, data_int, type, id);
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

    return ret;
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

    while ((packed_bytes>0) && (blob_pos[0]!=0x41 && blob_pos[0]!=0x42)){
        packed_bytes--;
        blob_pos++;
    };


    ret=1;
    while( (packed_bytes>0) && (ret==1) ){
        
        ret = unpack_4142 ((u32*)&new_list, &blob_pos, &packed_bytes, 0, 8, &list_size);
        ret = dump_41_list_getobj00 (&new_list, data_int, type, id);
        if (ret > 0) {
            return 1;
        }
        memset(&new_list, 0, sizeof(new_list));

        while ((packed_bytes>0) && (blob_pos[0]!=0x41 && blob_pos[0]!=0x42)){
            packed_bytes--;
            blob_pos++;
        };

    };
    
    return ret;
};


