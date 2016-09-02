//
// setup pkt 1
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../decode41.h"

extern int show_memory(char *mem, int len, char *text);
extern int set_packet_size(char *a1, int c);
extern int encode_to_7bit(char *buf, uint word, uint limit);

extern int make_41cmdencode(char *buf, int buf_len, uint blob_count, uint session_id, uint session_cmd, int dodebug);
extern int make_41encode(char *buf, int buf_len, char *blobptr, int dodebug);


extern u8 REMOTE_NAME[0x100];
extern u8 LOCAL_NAME[0x100];

extern u8 CLIENT_VERSION[0x100];

extern u32 LOCAL_SESSION_ID;
extern u8 LOCALNODE_VCARD[0x1B];
extern u8 REMOTENODE_VCARD[0x1B];

// local 64 bit challenge nonce
extern uint BLOB_1_9_size;
extern uint BLOB_1_9_ptr;


int encode41_setup1pkt(char *buf, int buf_limit_len){
	struct blob_s blob;
	uint session_id;
	uint session_cmd;

	int buf_len;
	int blob_count;


    //session_id=0x0285A1;

    session_id=0x01D1A1;
	//session_id = 0x01*0x10000 + (rand() % 0x1000);


	session_cmd=0x43;

	// 0x0D
	blob_count=13;

	memset(buf,0,sizeof(buf));
    buf_len=0;
    buf_len=make_41cmdencode(buf, buf_len, blob_count, session_id, session_cmd, 0);


    // blob1 -- local session id
    blob.obj_type = 0;
	blob.obj_index = 3;
    blob.obj_data = LOCAL_SESSION_ID;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	// blob2 -- localnode vcard
    blob.obj_type = 4;
	blob.obj_index = 1;
    blob.obj_data = 0;
	blob.data_ptr = (uint)LOCALNODE_VCARD;
	blob.data_size = sizeof(LOCALNODE_VCARD);
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	// blob3 -- 64 bit nonce
	// 64 bit challenge nonce in 43 41
	// size first byte > 0x7f000000 ...
    blob.obj_type = 1;
	blob.obj_index = 9;
    blob.obj_data = 0;
	blob.data_ptr = BLOB_1_9_ptr;
	blob.data_size = BLOB_1_9_size;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);
    
	// blob4 -- some flag
	blob.obj_type = 0;
	blob.obj_index = 0x1B;
    blob.obj_data = 0x06;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	// blob5 -- some flag2
	blob.obj_type = 0;
	blob.obj_index = 0x29;
    blob.obj_data = 0x04;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	// blob6 -- some flag3
	blob.obj_type = 0;
	blob.obj_index = 0x26;
    blob.obj_data = 0x01;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	// blob7 -- some flag4
	blob.obj_type = 0;
	blob.obj_index = 0x2A;
    blob.obj_data = 0x34;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	// blob8 -- our client version
	blob.obj_type = 0x03;
	blob.obj_index = 0x2B;
    blob.obj_data = 0;
	blob.data_ptr = (int)CLIENT_VERSION;
	blob.data_size = strlen(CLIENT_VERSION)+1;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	// blob9 -- remote skypename
	blob.obj_type = 3;
	blob.obj_index = 0;
    blob.obj_data = 0;
	blob.data_ptr = (int)REMOTE_NAME;
	blob.data_size = strlen(REMOTE_NAME)+1;
//	blob.data_ptr = (int)LOCAL_NAME;
//	blob.data_size = strlen(LOCAL_NAME)+1;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	// blob10 -- some flag5
	blob.obj_type = 0;
	blob.obj_index = 0x18;
    blob.obj_data = 1;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	// blob11 -- some flag6
	blob.obj_type = 0;
	blob.obj_index = 0x25;
    blob.obj_data = 0x10;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	// blob12 -- remotenode_vcard
    blob.obj_type = 0x04;
	blob.obj_index = 0x2C;
    blob.obj_data = 0;
	blob.data_ptr = (uint)REMOTENODE_VCARD;
	blob.data_size = sizeof(REMOTENODE_VCARD);
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	// blob 13 -- hz
	// size first byte > 0x7f000000 ...
    blob.obj_type = 0x01;
	blob.obj_index = 0x2D;
    blob.obj_data = 0;
	blob.data_ptr = 0x33FFE8A6;
	blob.data_size = 0xCB63DD4C;

	buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	if ( buf_len > buf_limit_len ){
		debuglog("buffer limit overrun\n");
		return -1;
	};

	return buf_len;
};


/*

setup1pkt

20:14:56.286 T#3488 Logger AES dump from 00914C97 len 92
20:14:56.286 T#3488 Before: 
20:14:56.286 T#3488 A1 D1 01 43 41 0D 00 03 E5 36 04 01 1B E0 3E 31 
20:14:56.286 T#3488 AE 40 3A E0 12 01 C0 A8 01 4B E1 08 41 37 DF 19 
20:14:56.286 T#3488 9C 55 75 03 25 C7 E1 08 01 09 B7 83 E9 A8 A9 0C 
20:14:56.286 T#3488 57 9A 00 1B 06 00 29 04 00 26 01 00 2A 34 03 2B 
20:14:56.286 T#3488 30 2F 36 2E 31 36 2E 30 2E 31 30 2F 2F 00 03 00 
20:14:56.286 T#3488 6E 6F 74 6E 6F 77 61 67 61 69 6E 70 6C 65 61 73 
20:14:56.286 T#3488 65 00 00 18 01 00 25 10 04 2C 1B 70 E7 DC 1C E2 
20:14:56.286 T#3488 82 8C 31 00 A8 3F 7D 7D 9C 5F 00 00 00 00 00 00 
20:14:56.286 T#3488 AC 1F FF F9 9C 5F 01 2D DD F2 77 F5 48 FE 53 51 
20:14:56.286 T#3488 06 9D 
===
PARAM send001
===
{
00-03: 65 1B 00 00
04-01: 27 bytes
0000: E0 3E 31 AE 40 3A E0 12 01 C0 A8 01 4B E1 08 41 | .>1.@:......K..A |
0010: 37 DF 19 9C 55 75 03 25 C7 E1 08                | 7...Uu.%...      |

01-09: A8 E9 83 B7 9A 57 0C A9
00-1B: 06 00 00 00
00-29: 04 00 00 00
00-26: 01 00 00 00
00-2A: 34 00 00 00
03-2B: "0/6.16.0.10//"
03-00: "notnowagainplease"
00-18: 01 00 00 00
00-25: 10 00 00 00
04-2C: 27 bytes
0000: 70 E7 DC 1C E2 82 8C 31 00 A8 3F 7D 7D 9C 5F 00 | p......1..?}}._. |
0010: 00 00 00 00 00 AC 1F FF F9 9C 5F                | .........._      |

01-2D: F5 77 F2 DD 51 53 FE 48
}
===

*/
