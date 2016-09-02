//
// Add on function for blob management
//

#include "skype_basics.h"
#include "skype_rc4.h"


///////////////////////
///////////////////////
///////////////////////

//
// search for all values
//
static int dump_41_list_getobj00_seq(const skype_list *list, u32 *data_int, int *count, int index, int type, int id) {
	u32				i, l;
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
			ret = dump_41_list_getobj00_seq((skype_list *)list->thing[i].m, data_int, count, index, type, id);
            if (ret) {
                return 1;
            };
			continue;
		};

		if ((list->thing[i].type == type) && (list->thing[i].id == id)) {
            if (0) {
                debuglog("Count = %d\n", *count);
                debuglog("Index = %d\n", index);
            };
            if ((*count) == index) {
    			*data_int=list->thing[i].m;
    			return 1;
            };
            (*count) = (*count) + 1;
		};

	}

	return ret;
}


//
// search for first value
//
int main_unpack_getobj00_seq (u8 *indata, u32 inlen, u32 *data_int, int index, int type, int id) {
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

	if (packed_bytes>0) {
		ret=unpack_4142 ((u32*)&new_list, &blob_pos, &packed_bytes, 0, 8, &list_size);
	};

    count = 0;
	ret = dump_41_list_getobj00_seq (&new_list, data_int, &count, index, type, id);
	
	return ret;
};


