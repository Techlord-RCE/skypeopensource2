//
// blob encode routines
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../decode41.h"

extern int show_memory(char *mem, int len, char *text);
extern int set_packet_size(char *a1, int c);
extern int encode_to_7bit(char *buf, uint word, uint limit);



int make_41cmdencode_recurs(char *buf, int buf_len, uint blob_count, int dodebug){

    // 41 encode marker
	buf[buf_len]=0x41;
	buf_len++;

	// number of blobs in 41 sequence
	buf[buf_len]=blob_count & 0xff;
	buf_len++;

	if (dodebug){
		show_memory(buf, buf_len, "blob header:");
	};

	return buf_len;

};



int make_41cmdencodeA6(char *buf, int buf_len, uint blob_count, uint session_id, uint session_cmd, int dodebug){

	// one byte of session cmd
	buf[buf_len]=0x00;
	buf_len++;

	// one byte of session cmd
	buf[buf_len]=session_cmd & 0xff;
	buf_len++;

	buf[buf_len]=0x01;
	buf_len++;

    // 41 encode marker
	buf[buf_len]=0x41;
	buf_len++;

	// number of blobs in 41 sequence
	buf[buf_len]=blob_count & 0xff;
	buf_len++;

	if (dodebug){
		show_memory(buf, buf_len, "blob header:");
	};

	return buf_len;

};

int make_41cmdencode(char *buf, int buf_len, uint blob_count, uint session_id, uint session_cmd, int dodebug){
	int len;


	// encode sess_id to 7bit
	//len=encode_to_7bit(buf+buf_len,session_id,10);
	//buf_len=buf_len+len;

	// no need 7bit encoding?
	
    if (session_id <= 0xFFFF) {
		// 2 bytes id
        memcpy(buf+buf_len, &session_id, 2);
        len=2;
	} else {
		// 3 bytes id
        memcpy(buf+buf_len, &session_id, 3);
        len=3;
    };

	buf_len=buf_len+len;

	// one byte of session cmd
	buf[buf_len]=session_cmd & 0xff;
	buf_len++;

    // 41 encode marker
	buf[buf_len]=0x41;
	buf_len++;

	// number of blobs in 41 sequence
	buf[buf_len]=blob_count & 0xff;
	buf_len++;

	if (dodebug){
		show_memory(buf, buf_len, "blob header:");
	};

	return buf_len;

};



int make_41encode(char *buf, int buf_len, char *blobptr, int dodebug){
	int len;
	struct blob_s *blob;
	blob=(struct blob_s *)blobptr;

	// hz
	// just hack for show 04-04 object before encoding
	if ( (blob->obj_type == 0x04) && (blob->obj_index == 0x04) ) {
		main_unpack(blob->data_ptr,blob->data_size);
		//show_memory(blob->data_ptr,blob->data_size, "BLOB_04_04:");
	};

	// encode type
	buf[buf_len]=blob->obj_type & 0xff;
	buf_len++;

	// 0x10FF just for test, not from code or reversed
	// for 04-EFEF blob fix
//	if ( blob->obj_index > 0x10FF ){
//		len=encode_to_7bit(buf+buf_len, blob->obj_index, 10);
//		buf_len=buf_len+len;
//	}else{
		// encode index
		buf[buf_len]=blob->obj_index & 0xff;
		buf_len++;
	//};


	// for newblk1, newblk2 41 data
	if ( (blob->obj_type == 0x06) && (blob->obj_index == 0x1B) ) {
            memcpy(buf+buf_len, &(blob->obj_data), blob->data_size);
			buf_len=buf_len+blob->data_size;
			return buf_len;
	};


	if (blob->obj_data>0){
		// encode obj_data to 7bit
		len=encode_to_7bit(buf+buf_len, blob->obj_data, 10);
		buf_len=buf_len+len;
	};


	//  depends on data_size
	if ( (blob->data_size==0) && (blob->obj_data==0) ){
		
		// set data_size to 0
		buf[buf_len]=0;
		buf_len++;

	};
	if ( (blob->data_size>0) && (blob->data_size<0x007f0000) ){

		if ( (blob->obj_type==3) || (blob->obj_type==5) ){
		//if ( (blob->obj_type==3) || (blob->obj_type==5) || (blob->obj_type==6) ){

		} else {

			if ( (blob->data_size > 0) && (blob->data_size <= 0x7F) ){
				// encode size
				buf[buf_len]=blob->data_size & 0xff;
				buf_len++;
			};

			if (blob->data_size > 0x7F){
				len=encode_to_7bit(buf+buf_len, blob->data_size, 10);
				buf_len=buf_len+len;
			};

		};

		// encode object
		memcpy(buf+buf_len, (char *)blob->data_ptr, blob->data_size );
		buf_len = buf_len + blob->data_size;


	};
	if (blob->data_size>0x007f0000){

		// encode data_size bytes as is
		blob->data_size=bswap32(blob->data_size);
		memcpy( buf+buf_len, (char *)&blob->data_size, 4 );
		buf_len=buf_len+4;
		blob->data_size=bswap32(blob->data_size);

		// encode data_ptr bytes as is
		blob->data_ptr=bswap32(blob->data_ptr);
		memcpy( buf+buf_len, (char *)&blob->data_ptr, 4 );
		buf_len=buf_len+4;
		blob->data_ptr=bswap32(blob->data_ptr);

	};

	if (dodebug){
		show_memory(buf, buf_len, "blob");
	};
	
	return buf_len;
};


int make_41encode_type6(char *buf, int buf_len, char *blobptr, int dodebug) {
	int len;
	struct blob_s *blob;
	blob=(struct blob_s *)blobptr;

	// encode type
	buf[buf_len]=blob->obj_type & 0xff;
	buf_len++;

    // encode index
	buf[buf_len]=blob->obj_index & 0xff;
	buf_len++;

	if (blob->obj_type == 0x06) {

        if ((blob->obj_index == 0x34) || (blob->obj_index == 0x4D)) {

      		buf[buf_len]=blob->obj_data & 0xFF;
           	buf_len++;

    		// encode obj_data to 7bit
    		len=encode_to_7bit(buf+buf_len, blob->data_ptr, 10);
    		buf_len=buf_len+len;

	       	len=encode_to_7bit(buf+buf_len, blob->data_size, 10);
            buf_len=buf_len+len;
        };

	};


	if (dodebug){
		show_memory(buf, buf_len, "blob");
	};
	
	return buf_len;
};


//////////////////////////////////////////////////////////
int encode41_sesspkt_ack(char *buf, int buf_limit_len, uint cmd){
	uint session_id;
	uint session_cmd;
	int buf_len;

	session_id=cmd;
	session_cmd=0x47;

	memset(buf,0,sizeof(buf));
    buf_len=0;
    buf_len=make_41cmdencode(buf, buf_len, 0, session_id, session_cmd, 0);



	if ( buf_len > buf_limit_len ){
		debuglog("buffer limit overrun\n");
		return -1;
	};

	return buf_len;

};





//////////////////////////////////////////////////////////
int encode41_sesspkt_A6_ack(char *buf, int buf_limit_len, int A6_sessid){
	struct blob_s blob;
	uint session_id;
	uint session_cmd;
	int buf_len;
	int blob_count;

	session_id=00;
	session_cmd=0xA6;

	memset(buf,0,sizeof(buf));
    buf_len=0;

	blob_count = 2;
    buf_len=make_41cmdencodeA6(buf, buf_len, blob_count, session_id, session_cmd, 0);


	// hz .. blob1
    blob.obj_type = 0;
	blob.obj_index = 0;
    blob.obj_data = 0x02;
	blob.data_ptr = 0;
	blob.data_size = 0;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // ack code --  blob2
	// 4 - confirm ok
	// 5 - cmd id error
    blob.obj_type = 0;	
	blob.obj_index = 4;
	blob.obj_data = A6_sessid;
	blob.data_ptr = 0;
	blob.data_size = 0;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	if ( buf_len > buf_limit_len ){
		debuglog("buffer limit overrun\n");
		return -1;
	};

	return buf_len;
};


