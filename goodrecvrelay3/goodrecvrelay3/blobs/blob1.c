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

    //u8 remote_name[]="xot_iam";
	//local_session_id=0x249F;

	int buf_len;
	int blob_count;


	//session_id=0x4DDD;
    session_id=0x0285A1;

	session_cmd=0x43;

	// 0x0D
	blob_count=13;

	memset(buf,0,sizeof(buf));
    buf_len=0;
    buf_len=make_41cmdencode(buf, buf_len, blob_count, session_id, session_cmd, 0);


    // blob1 -- local session id
    blob.obj_type = 0;
	blob.obj_index = 3;
    blob.obj_data = LOCAL_SESSION_ID;;
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
    blob.obj_data = 0x08;
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
    blob.obj_data = 0x08;
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
	//blob.data_ptr = 0xE0598A67;
	//blob.data_size = 0xDA3824A6;
	blob.data_ptr = 0x33FFE8A6;
	blob.data_size = 0xCB63DD4C;

	buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

/*
	// blob 14 -- hz
	// size first byte > 0x7f000000 ...
    blob.obj_type = 0x01;
	blob.obj_index = 0x2E;
    blob.obj_data = 0;
	blob.data_ptr = 0x1C666761;
	blob.data_size = 0x17661B5E;
	
	buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);
*/

	if ( buf_len > buf_limit_len ){
		debuglog("buffer limit overrun\n");
		return -1;
	};

	return buf_len;
};


/*

setup1pkt

===
20:32:11.331 T#1348 Logger AES dump from 00914C97 len 93
20:32:11.346 T#1348 Before: 
20:32:11.346 T#1348 A1 85 02 43 41 0D 00 03 A5 B8 01 04 01 1B 65 03 
20:32:11.346 T#1348 23 5A 28 22 17 37 01 C0 A8 01 87 5B 73 9D 37 EB 
20:32:11.346 T#1348 8F 9C 55 B2 41 2C 15 5B 73 01 09 73 B9 91 34 45 
20:32:11.346 T#1348 40 A9 FC 00 1B 08 00 29 04 00 26 01 00 2A 34 03 
20:32:11.346 T#1348 2B 30 2F 35 2E 35 2E 30 2E 31 32 34 2F 2F 00 03 
20:32:11.346 T#1348 00 6E 6F 74 6E 6F 77 61 67 61 69 6E 70 6C 65 61 
20:32:11.346 T#1348 73 65 00 00 18 01 00 25 08 04 2C 1B 7B 95 38 E8 
20:32:11.346 T#1348 7D 6E 31 3E 01 C0 A8 01 4B E1 08 6F DD 4D 9E 9C 
20:32:11.346 T#1348 4C B2 41 2C 15 E1 08 01 2D CB 63 DD 4C 33 FF E8 
20:32:11.346 T#1348 A6 F7 6B 
===
PARAM send0001
===
{
00-03: 25 5C 00 00
04-01: 27 bytes
0000: 65 03 23 5A 28 22 17 37 01 C0 A8 01 87 5B 73 9D | e.#Z(".7.....[s. |
0010: 37 EB 8F 9C 55 B2 41 2C 15 5B 73                | 7...U.A,.[s      |

01-09: 34 91 B9 73 FC A9 40 45
00-1B: 08 00 00 00
00-29: 04 00 00 00
00-26: 01 00 00 00
00-2A: 34 00 00 00
03-2B: "0/5.5.0.124//"
03-00: "notnowagainplease"
00-18: 01 00 00 00
00-25: 08 00 00 00
04-2C: 27 bytes
0000: 7B 95 38 E8 7D 6E 31 3E 01 C0 A8 01 4B E1 08 6F | {.8.}n1>....K..o |
0010: DD 4D 9E 9C 4C B2 41 2C 15 E1 08                | .M..L.A,...      |

01-2D: 4C DD 63 CB A6 E8 FF 33
}
===

*/
