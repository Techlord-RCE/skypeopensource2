//
// Add on function for blob management
//

#include "skype_basics.h"
#include "skype_rc4.h"


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

    while ((packed_bytes>0) && (blob_pos[0]!=0x41 && blob_pos[0]!=0x42)){
        packed_bytes--;
        blob_pos++;
    };


    ret=1;
    while( (packed_bytes>0) && (ret==1) ){
        
        ret = unpack_4142 ((u32*)&new_list, &blob_pos, &packed_bytes, 0, 8, &list_size);
        ret = dump_41_list_checkblob(&new_list, type, id);
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
