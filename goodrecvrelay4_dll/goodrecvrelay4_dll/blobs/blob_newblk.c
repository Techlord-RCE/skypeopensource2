//
// session newblk
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../decode41.h"

extern int show_memory(char *mem, int len, char *text);
extern int set_packet_size(char *a1, int c);
extern int encode_to_7bit(char *buf, uint word, uint limit);

extern int make_41cmdencode_recurs(char *buf, int buf_len, uint blob_count, int dodebug);
extern int make_41cmdencode(char *buf, int buf_len, uint blob_count, uint session_id, uint session_cmd, int dodebug);
extern int make_41encode(char *buf, int buf_len, char *blobptr, int dodebug);



extern u8 MSG_TEXT[0x100];
extern u8 CHAT_STRING[0x100];
extern u8 CHAT_PEERS[0x100];
extern u8 CREDENTIALS[0x105];
extern uint CREDENTIALS_LEN;
extern u8 NEWBLK[0x1000];
extern uint NEWBLK_LEN;
extern u8 REMOTE_NAME[0x100];

extern u8 LOCALNODE_VCARD[0x1B];

extern uint BLOB_0_5;
extern uint BLOB_0_5__1;
extern uint BLOB_0_6;
extern uint BLOB_0_7__2;
extern uint BLOB_0_7__3;
extern uint BLOB_0_7__4;
extern uint BLOB_0_A__2;
extern uint BLOB_0_A__3;


extern uint HEADER_ID_REMOTE_LAST;
extern uint HEADER_ID_SEND;


extern uint START_HEADER_ID;
extern uint global_unknown_cmd24_signed_id;
extern uint global_unknown_cmd2A_signed_id;

extern uint global_unknown_cmd24_time;
extern uint global_unknown_cmd24_time_sec;
extern uint global_unknown_cmd24_blob1b;


//
// chatinit sign cmd24 (newblk1)
//
int encode41_newblk1(char *buf, int buf_limit_len){
	struct blob_s blob;
	int buf_len;
	int blob_count;

	char intbuf[0x1000];
	int intbuf_len;

	memset(buf,0,sizeof(buf));
    buf_len=0;

	blob_count = 9;

    buf_len=make_41cmdencode_recurs(buf, buf_len, blob_count, 0);

    // some flag -- blob1
    blob.obj_type = 0;
	blob.obj_index = 0;
    blob.obj_data = 1;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // LOCALNODE_VCARD -- blob2
    blob.obj_type = 4;
	blob.obj_index = 3;
    blob.obj_data = 0;
	blob.data_ptr = (int)LOCALNODE_VCARD;
	blob.data_size = sizeof(LOCALNODE_VCARD);
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // timestamp in seconds -- blob3
    blob.obj_type = 0;
	blob.obj_index = 5;
	blob.obj_data = time(NULL);
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // timestamp in minutes -- blob4
    blob.obj_type = 0;
	blob.obj_index = 6;
    //blob.obj_data = 0x013AF0D7;
	blob.obj_data = time(NULL) / 60;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	// HEADER_ID_NEW (first header appear) -- blob5
    blob.obj_type = 0;
	blob.obj_index = 7;
	//blob.obj_data = BLOB_0_7__2;
    //blob.obj_data = 0x3D98FDA0;
	//blob.obj_data = 0x393841CB;
	//blob.obj_data = 0x1B2BE2D2;
    //blob.obj_data = 0x16352BA9;
    blob.obj_data = START_HEADER_ID;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	// remote peer name -- blob6
    blob.obj_type = 3;
	blob.obj_index = 1;
    blob.obj_data = 0;
	blob.data_ptr = (int)REMOTE_NAME;
	blob.data_size = strlen(REMOTE_NAME)+1;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	// some wrapper unk_header -- blob7
    blob.obj_type = 0;
	blob.obj_index = 0x0A;
	//blob.obj_data = BLOB_0_A__2;
    //blob.obj_data = 0x08DD772A;
	//blob.obj_data = 0x710F3804;
	//blob.obj_data = 0x21D598C5;
	blob.obj_data = global_unknown_cmd24_signed_id;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	// some unknow blob with new type -- blob8
    blob.obj_type = 6;
	blob.obj_index = 0x1B;
    blob.obj_data = 0x010B0000;
	blob.data_ptr = 0;
	blob.data_size = 4;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	if ( buf_len > buf_limit_len ){
		debuglog("buffer limit overrun\n");
		return -1;
	};

	return buf_len;
};


/*

newblk1

===
SIGNED TEXT
===
recovered signed data:
Len: 0x000000A0
6A 6B 63 02 9A 57 6C 59 EC 36 22 B6 15 7B BB FE  ; jkc  WlY 6"  {  
 71 18 6F F3 14 23 74 68 65 6D 61 67 69 63 66 6F  ; q o  #themagicfo
 72 79 6F 75 2F 24 6E 6F 74 6E 6F 77 61 67 61 69  ; ryou/$notnowagai
 6E 70 6C 65 61 73 65 3B 62 63 35 66 66 64 39 32  ; nplease;bc5ffd92
 39 39 31 33 32 65 61 35 41 09 00 00 01 04 03 1B  ; 99132ea5A       
 65 03 23 5A 28 22 17 37 01 C0 A8 01 87 5B 73 9D  ; e #Z(" 7     [s 
 37 EB 8F 9C 55 B2 41 2C 15 5B 73 00 05 85 97 EB  ; 7   U A, [s     
 9D 05 00 06 8F FE 94 0B 00 07 A9 D7 D4 B1 01 03  ;                 
 01 6E 6F 74 6E 6F 77 61 67 61 69 6E 70 6C 65 61  ;  notnowagainplea
 73 65 00 00 0A C5 B1 D6 8E 02 06 1B 00 00 0B 01  ; se              
 
{
00-00: 01 00 00 00
04-03: 27 bytes
0000: 65 03 23 5A 28 22 17 37 01 C0 A8 01 87 5B 73 9D | e.#Z(".7.....[s. |
0010: 37 EB 8F 9C 55 B2 41 2C 15 5B 73                | 7...U.A,.[s      |

00-05: 85 CB BA 53
00-06: 0F 3F 65 01
00-07: A9 2B 35 16
03-01: "notnowagainplease"
00-0A: C5 98 D5 21
06-1B: 
00-0B: 01 00 00 00
}
===


00-05: 85 CB BA 53
00-06: 0F 3F 65 01
^^ time

00-07: A9 2B 35 16
^^ start header id

00-0A: C5 98 D5 21
^^ unknown_cmd24_signed_id
(used in SYNCER session close packet later)

===

*/

 
//
// newblk2 (data before signing)
//
int encode41_newblk2(char *buf, int buf_limit_len){
	struct blob_s blob;
	int buf_len;
	int blob_count;
	u8 str_null[]="";

	memset(buf,0,sizeof(buf));
    buf_len=0;

	blob_count = 9;

    buf_len=make_41cmdencode_recurs(buf, buf_len, blob_count, 0);

    // some flag -- blob1
    blob.obj_type = 0;
	blob.obj_index = 0;
    blob.obj_data = 4;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // LOCALNODE_VCARD -- blob2
    blob.obj_type = 4;
	blob.obj_index = 3;
    blob.obj_data = 0;
	blob.data_ptr = (int)LOCALNODE_VCARD;
	blob.data_size = sizeof(LOCALNODE_VCARD);
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // unix timestamp in seconds -- blob3
    blob.obj_type = 0;
	blob.obj_index = 5;
	//blob.obj_data = BLOB_0_5;
    //blob.obj_data = 0x49D079E2;
	blob.obj_data = time(NULL);
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // unix timestamp in minutes -- blob4
    blob.obj_type = 0;
	blob.obj_index = 6;
	//blob.obj_data = BLOB_0_6;
    //blob.obj_data = 0x013AF0D7;
	blob.obj_data = time(NULL) / 60;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	// header_id (start_header_id - 1) -- blob5
    blob.obj_type = 0;
	blob.obj_index = 7;
	//blob.obj_data = BLOB_0_7__3;
    //blob.obj_data = 0x1B2BE2D2;
    //blob.obj_data = 0x16352BA8;
    blob.obj_data = START_HEADER_ID - 1;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	// just empty string -- blob6
    blob.obj_type = 3;
	blob.obj_index = 0x0E;
    blob.obj_data = 0;
	blob.data_ptr = (int)str_null;
	blob.data_size = strlen(str_null)+1;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	// some flag -- blob7
    blob.obj_type = 0;
	blob.obj_index = 0x0F;
    blob.obj_data = 0;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	// unknown_cmd2A_signed_id -- blob8
    blob.obj_type = 0;
	blob.obj_index = 0x0A;
    //blob.obj_data = 0x1C6089DF;
    //blob.obj_data = 0x440E8922;    
    blob.obj_data = global_unknown_cmd2A_signed_id;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	// some unknow blob with new type -- blob9
    blob.obj_type = 6;
	blob.obj_index = 0x1B;
    blob.obj_data = 0x0;
	blob.data_ptr = 0;
	blob.data_size = 1;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	if ( buf_len > buf_limit_len ){
		debuglog("buffer limit overrun\n");
		return -1;
	};

	return buf_len;
};



/*

newblk2

===
SIGNED TEXT
===
recovered signed data:
Len: 0x0000008F
6A 6B 63 02 9A 57 6C 59 EC 36 22 B6 15 7B BB FE  ; jkc  WlY 6"  {  
 71 18 6F F3 14 23 74 68 65 6D 61 67 69 63 66 6F  ; q o  #themagicfo
 72 79 6F 75 2F 24 6E 6F 74 6E 6F 77 61 67 61 69  ; ryou/$notnowagai
 6E 70 6C 65 61 73 65 3B 62 63 35 66 66 64 39 32  ; nplease;bc5ffd92
 39 39 31 33 32 65 61 35 41 09 00 00 04 04 03 1B  ; 99132ea5A       
 65 03 23 5A 28 22 17 37 01 C0 A8 01 87 5B 73 9D  ; e #Z(" 7     [s 
 37 EB 8F 9C 55 B2 41 2C 15 5B 73 00 05 85 97 EB  ; 7   U A, [s     
 9D 05 00 06 8F FE 94 0B 00 07 A8 D7 D4 B1 01 03  ;                 
 0E 00 00 0F 00 00 0A A2 92 BA A0 04 06 1B 00 
{
00-00: 04 00 00 00
04-03: 27 bytes
0000: 65 03 23 5A 28 22 17 37 01 C0 A8 01 87 5B 73 9D | e.#Z(".7.....[s. |
0010: 37 EB 8F 9C 55 B2 41 2C 15 5B 73                | 7...U.A,.[s      |

00-05: 85 CB BA 53
00-06: 0F 3F 65 01
00-07: A8 2B 35 16
03-0E: ""
00-0F: 00 00 00 00
00-0A: 22 89 0E 44
06-1B: 
}
===

00-05: 85 CB BA 53
00-06: 0F 3F 65 01
^^ time

00-07: A8 2B 35 16
^^ (start header id - 1)

00-0A: 22 89 0E 44
^^ unknown_cmd2A_signed_id
===

*/



int encode41_newblk3(char *buf, int buf_limit_len){
	struct blob_s blob;
	int buf_len;
	int blob_count;

	memset(buf,0,sizeof(buf));
    buf_len=0;

	blob_count = 7;

    buf_len=make_41cmdencode_recurs(buf, buf_len, blob_count, 0);

    // seq id NEWBLK3 for sha-1 hashing -- blob1
    blob.obj_type = 0;
	blob.obj_index = 0;
    blob.obj_data = 3;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // LOCALNODE_VCARD -- blob2
    blob.obj_type = 4;
	blob.obj_index = 3;
    blob.obj_data = 0;
	blob.data_ptr = (int)LOCALNODE_VCARD;
	blob.data_size = sizeof(LOCALNODE_VCARD);
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // unix timestamp in seconds -- blob3
    blob.obj_type = 0;
	blob.obj_index = 5;
    blob.obj_data = time(NULL);
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // unix timestamp in minutes -- blob4
    blob.obj_type = 0;
	blob.obj_index = 6;
    //blob.obj_data = 0x01653F0F;
    blob.obj_data = time(NULL) / 60;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	// START_HEADER_ID  -- blob5
    blob.obj_type = 0;
	blob.obj_index = 7;
	blob.obj_data = START_HEADER_ID + 1;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	// some flag info -- blob6
    blob.obj_type = 0;
	blob.obj_index = 0x44;
    blob.obj_data = 0x01;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	// clear chat text data -- blob7
    blob.obj_type = 3;
	blob.obj_index = 2;
    blob.obj_data = 0;
	blob.data_ptr = (int)MSG_TEXT;
	blob.data_size = strlen(MSG_TEXT)+1;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	if ( buf_len > buf_limit_len ){
		debuglog("buffer limit overrun\n");
		return -1;
	};

	return buf_len;
};



/*

newblk3

===
SIGNED TEXT
===
recovered signed data:
Len: 0x0000008D
6A 6B 63 02 9A 57 6C 59 EC 36 22 B6 15 7B BB FE  ; jkc  WlY 6"  {  
 71 18 6F F3 14 23 74 68 65 6D 61 67 69 63 66 6F  ; q o  #themagicfo
 72 79 6F 75 2F 24 6E 6F 74 6E 6F 77 61 67 61 69  ; ryou/$notnowagai
 6E 70 6C 65 61 73 65 3B 62 63 35 66 66 64 39 32  ; nplease;bc5ffd92
 39 39 31 33 32 65 61 35 41 07 00 00 03 04 03 1B  ; 99132ea5A       
 65 03 23 5A 28 22 17 37 01 C0 A8 01 87 5B 73 9D  ; e #Z(" 7     [s 
 37 EB 8F 9C 55 B2 41 2C 15 5B 73 00 05 8B 97 EB  ; 7   U A, [s     
 9D 05 00 06 8F FE 94 0B 00 07 AA D7 D4 B1 01 00  ;                 
 44 01 03 02 74 65 73 74 33 33 34 35 00 
{
00-00: 03 00 00 00
04-03: 27 bytes
0000: 65 03 23 5A 28 22 17 37 01 C0 A8 01 87 5B 73 9D | e.#Z(".7.....[s. |
0010: 37 EB 8F 9C 55 B2 41 2C 15 5B 73                | 7...U.A,.[s      |

00-05: 8B CB BA 53
00-06: 0F 3F 65 01
00-07: AA 2B 35 16
00-44: 01 00 00 00
03-02: "test3345"
}
===

*/


int encode41_newblk4(char *buf, int buf_limit_len){
	struct blob_s blob;
	int buf_len;
	int blob_count;

	memset(buf,0,sizeof(buf));
    buf_len=0;

	blob_count = 9;

    buf_len=make_41cmdencode_recurs(buf, buf_len, blob_count, 0);

    // seq id NEWBLK3 for sha-1 hashing -- blob1
    blob.obj_type = 0;
	blob.obj_index = 0;
    blob.obj_data = 4;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // LOCALNODE_VCARD -- blob2
    blob.obj_type = 4;
	blob.obj_index = 3;
    blob.obj_data = 0;
	blob.data_ptr = (int)LOCALNODE_VCARD;
	blob.data_size = sizeof(LOCALNODE_VCARD);
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // unix timestamp in seconds -- blob3
    blob.obj_type = 0;
	blob.obj_index = 5;
    //blob.obj_data = time(NULL);
    blob.obj_data = global_unknown_cmd24_time_sec;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // unix timestamp in minutes -- blob4
    blob.obj_type = 0;
	blob.obj_index = 6;
    //blob.obj_data = time(NULL) / 60;
    blob.obj_data = global_unknown_cmd24_time;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	// START_HEADER_ID  -- blob5
    blob.obj_type = 0;
	blob.obj_index = 7;
	//blob.obj_data = START_HEADER_ID + 1;
	blob.obj_data = START_HEADER_ID;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	// clear chat text data -- blob6
    blob.obj_type = 3;
	blob.obj_index = 0x0E;
    blob.obj_data = 0;
	//blob.data_ptr = (int)MSG_TEXT;
	//blob.data_size = strlen(MSG_TEXT)+1;
	blob.data_ptr = (int)REMOTE_NAME;
	blob.data_size = strlen(REMOTE_NAME)+1;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	// some flag -- blob7
    blob.obj_type = 0;
	blob.obj_index = 0x0F;
    //blob.obj_data = 0x0174;
    blob.obj_data = global_unknown_cmd24_blob1b;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	// header from cmd24 -- blob8
    blob.obj_type = 0;
	blob.obj_index = 0x0A;
    //blob.obj_data = 0xC598D521;
	blob.obj_data = global_unknown_cmd24_signed_id;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	// some flag -- blob9
    blob.obj_type = 6;
	blob.obj_index = 0x1B;
    blob.obj_data = 0x00;
	blob.data_ptr = 0;
	blob.data_size = 1;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	if ( buf_len > buf_limit_len ){
		debuglog("buffer limit overrun\n");
		return -1;
	};

	return buf_len;
};


/*

===
SIGNED TEXT
===
recovered signed data:
Len: 0x0000009D
6A C4 5A 56 C4 BA 85 BF 29 55 06 7B B3 36 DF 7E  ; j ZV    )U { 6 ~
 42 40 68 A0 8E 23 74 68 65 6D 61 67 69 63 66 6F  ; B@h  #themagicfo
 72 79 6F 75 2F 24 6E 6F 74 6E 6F 77 61 67 61 69  ; ryou/$notnowagai
 6E 70 6C 65 61 73 65 3B 32 33 39 37 39 35 34 65  ; nplease;2397954e
 30 31 31 63 63 39 35 31 41 09 00 00 04 04 03 1B  ; 011cc951A       
 E0 3E 31 AE 40 3A E0 12 01 C0 A8 01 4B E1 08 41  ;  >1 @:      K  A
 37 DF 19 9C 55 75 03 25 C7 E1 08 00 05 DE D8 A5  ; 7   Uu %        
 B2 05 00 06 9B D0 C0 0B 00 07 B3 C3 AA BD 02 03  ;                 
 0E 74 68 65 6D 61 67 69 63 66 6F 72 79 6F 75 00  ;  themagicforyou 
 00 0F F4 02 00 0A B6 90 ED 24 06 1B 00 
{
00-00: 04 00 00 00
04-03: 27 bytes
0000: E0 3E 31 AE 40 3A E0 12 01 C0 A8 01 4B E1 08 41 | .>1.@:......K..A |
0010: 37 DF 19 9C 55 75 03 25 C7 E1 08                | 7...Uu.%...      |

00-05: 5E 6C 49 56
00-06: 1B 28 70 01
00-07: B3 A1 AA 27
03-0E: "themagicforyou"
00-0F: 74 01 00 00
00-0A: 36 48 9B 04
06-1B: 
}
===

time:
00-05: 5E 6C 49 56 in seconds
00-06: 1B 28 70 01 in minutes (sec/60)

header_id:
00-07: B3 A1 AA 27

from cmd24:
00-0A: 36 48 9B 04

blob1b

*/
