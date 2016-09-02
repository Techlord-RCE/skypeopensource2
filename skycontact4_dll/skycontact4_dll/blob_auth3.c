//
// auth pkt 3
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


int encode41_auth3pkt(char *buf, int buf_limit_len,
            unsigned int sess_id, unsigned int pkt_id){
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
    //blob.obj_data = 0x178C;
    blob.obj_data = sess_id;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	// blob2
	blob.obj_type = 0;
	blob.obj_index = 2;
    //blob.obj_data = 0x04;
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

	second_len = encode41_auth3pkt_second(buf+buf_len, buf_limit_len);
	buf_len = buf_len + second_len;

	return buf_len;
};


int encode41_auth3pkt_second(char *buf, int buf_limit_len){
	struct blob_s blob;
	uint session_id;
	uint session_cmd;
	int buf_len;
	int blob_count;

	blob_count=4;

    buf_len=0;
    buf_len=make_41cmdencode_auth(buf, buf_len, blob_count, 0);

    // blob1 -- hostid1 8 bytes
    blob.obj_type = 0x01;
	blob.obj_index = 0x3A;
    blob.obj_data = 0;
	blob.data_ptr = 0x48FB45AF;
	blob.data_size = 0x9ACA0BBB; 
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

PKT3

"\x41\x04\x00\x00\x8C\x2F\x00\x02\x04\x03\x04\x74\x68\x65\x6D\x61"
"\x67\x69\x63\x66\x6F\x72\x79\x6F\x75\x00\x04\x05\x10\xFC\x9D\x77"
"\xE4\xA7\x40\x93\xD5\x75\xA4\xC3\xFA\x27\x4A\x4B\x6A\x41\x04\x01"
"\x3A\x9A\xCA\x0B\xBB\x48\xFB\x45\xAF\x03\x04\x74\x68\x65\x6D\x61"
"\x67\x69\x63\x66\x6F\x72\x79\x6F\x75\x00\x03\x0D\x30\x2F\x36\x2E"
"\x31\x36\x2E\x30\x2E\x31\x30\x2F\x2F\x00\x00\x0E\xFA\xD6\xD3\xF9"
"\x05"
;


{
00-00: 8C 17 00 00
00-02: 04 00 00 00
03-04: "themagicforyou"
04-05: 16 bytes
0000: FC 9D 77 E4 A7 40 93 D5 75 A4 C3 FA 27 4A 4B 6A

}

{
01-3A: BB 0B CA 9A AF 45 FB 48
03-04: "themagicforyou"
03-0D: "0/6.16.0.10//"
00-0E: 7A EB 34 5F
}

*/
