//
// auth pkt 7
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "decode41.h"

extern int show_memory(char *mem, int len, char *text);
extern int set_packet_size(char *a1, int c);
extern int encode_to_7bit(char *buf, uint word, uint limit);

extern int make_41cmdencode(char *buf, int buf_len, uint blob_count, uint session_id, uint session_cmd, int dodebug);
extern int make_41encode(char *buf, int buf_len, char *blobptr, int dodebug);


extern u8 LOCAL_NAME[0x100];
extern u8 CLIENT_VERSION[0x100];
extern u8 LOCAL_AUTH_BUF[0x11];


int encode41_auth7pkt(char *buf, int buf_limit_len, 
            unsigned int sess_id, unsigned int pkt_id, unsigned int sync_idx){

	struct blob_s blob;
	uint session_id;
	uint session_cmd;
	int buf_len;
	int blob_count;
	int second_len;

	blob_count=4;

	memset(buf,0,sizeof(buf));
    buf_len=0;
    buf_len=make_41cmdencode_auth(buf, buf_len, blob_count, 0);


    // blob1 
    blob.obj_type = 0;
	blob.obj_index = 0;
    //blob.obj_data = 0x1780;
    blob.obj_data = sess_id;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	// blob2
	blob.obj_type = 0;
	blob.obj_index = 2;
    //blob.obj_data = 0x0B;
    blob.obj_data = pkt_id;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	// blob3 -- local skypename
	blob.obj_type = 3;
	blob.obj_index = 4;
    blob.obj_data = 0;
	blob.data_ptr = (int)LOCAL_NAME;
	blob.data_size = strlen(LOCAL_NAME)+1;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // blob4 -- some...
    blob.obj_type = 4;
	blob.obj_index = 5;
    blob.obj_data = 0;
	blob.data_ptr = (int)LOCAL_AUTH_BUF;
	blob.data_size = sizeof(LOCAL_AUTH_BUF)-1;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	if ( buf_len > buf_limit_len ){
		printf("buffer limit overrun\n");
		return -1;
	};

	second_len = encode41_auth7pkt_second(buf+buf_len, buf_limit_len, sync_idx);
	buf_len = buf_len + second_len;

	return buf_len;
};


int encode41_auth7pkt_second(char *buf, int buf_limit_len, unsigned int sync_idx){
	struct blob_s blob;
	uint session_id;
	uint session_cmd;
	int buf_len;
	int blob_count;

	blob_count=4;

    buf_len=0;
    buf_len=make_41cmdencode_auth(buf, buf_len, blob_count, 0);

	// blob1
	blob.obj_type = 0;
	blob.obj_index = 0x2D;
    //blob.obj_data = 0x00000000;
    blob.obj_data = sync_idx;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	// blob2
	blob.obj_type = 3;
	blob.obj_index = 4;
    blob.obj_data = 0;
	blob.data_ptr = (int)LOCAL_NAME;
	blob.data_size = strlen(LOCAL_NAME)+1;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	// blob3 -- our client version
	blob.obj_type = 0x03;
	blob.obj_index = 0x0D;
    blob.obj_data = 0;
	blob.data_ptr = (int)CLIENT_VERSION;
	blob.data_size = strlen(CLIENT_VERSION)+1;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	// blob4
	blob.obj_type = 0;
	blob.obj_index = 0x0E;
    blob.obj_data = 0x5F34EB7A;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	if ( buf_len > buf_limit_len ){
		printf("buffer limit overrun\n");
		return -1;
	};

	return buf_len;
};


/*

PKT9

 41 04 00 00 80 2F 00 02 0C 03 04 74 68 65 6D 61 
 67 69 63 66 6F 72 79 6F 75 00 04 05 10 FC 9D 77 
 E4 A7 40 93 D5 75 A4 C3 FA 27 4A 4B 6A 41 04 00 
 2D 00 03 04 74 68 65 6D 61 67 69 63 66 6F 72 79 
 6F 75 00 03 0D 30 2F 36 2E 31 36 2E 30 2E 31 30 
 2F 2F 00 00 0E FA D6 D3 F9 05 
===
{
00-00: 80 17 00 00
00-02: 0C 00 00 00
03-04: "themagicforyou"
04-05: 16 bytes
0000: FC 9D 77 E4 A7 40 93 D5 75 A4 C3 FA 27 4A 4B 6A | ..w..@..u...'JKj |

}

{
00-2D: 00 00 00 00
03-04: "themagicforyou"
03-0D: "0/6.16.0.10//"
00-0E: 7A EB 34 5F
}

===

*/
