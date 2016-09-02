//
// Login pkt
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
extern u8 PUBLIC_KEY[0x81];


u8 LANGUAGE[0x100]=
"en"
;

u8 BUF_06_33[0x14+1] = 
"\xAF\x45\xFB\x48\x32\xC8\xF8\x34\xF0\x13\x29\x00\xBD\xA0\x6E\xC4"
"\xED\x50\x54\x21"
;

u8 VCARD[0x1B+1] = 
"\x65\xF1\x24\x41\x7C\x03\x6C\x95\x01\xC0\xA8\x01\x4B\xE1\x08\x40"
"\x04\x17\xB0\x9C\x46\xB2\x41\x32\xAE\xE1\x08"
;

//
// login pkt ok
//
int encode41_loginpkt(char *buf, int buf_limit_len){
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
    blob.obj_data = 0x13A3;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	// blob2
	blob.obj_type = 0;
	blob.obj_index = 2;
    blob.obj_data = 0x01;
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

    // blob4 -- auth buffer
    blob.obj_type = 4;
	blob.obj_index = 5;
    blob.obj_data = 0;
	blob.data_ptr = (int)LOCAL_AUTH_BUF;
	blob.data_size = sizeof(LOCAL_AUTH_BUF)-1;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	if ( buf_len > buf_limit_len ){
		printf("buffer limit overrun\n");
		exit(1);
	};

	second_len = encode41_loginpkt_second(buf+buf_len, buf_limit_len);
	buf_len = buf_len + second_len;

	return buf_len;
};


int encode41_loginpkt_second(char *buf, int buf_limit_len){
	struct blob_s blob;
	uint session_id;
	uint session_cmd;
	int buf_len;
	int blob_count;

	blob_count = 7;

    buf_len=0;
    buf_len=make_41cmdencode_auth(buf, buf_len, blob_count, 0);

    // blob1 -- public key buffer
    blob.obj_type = 4;
	blob.obj_index = 0x21;
    blob.obj_data = 0;
	blob.data_ptr = (int)PUBLIC_KEY;
	blob.data_size = sizeof(PUBLIC_KEY)-1;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	// blob2 -- (hostid1?) 8 bytes
    blob.obj_type = 0x01;
	blob.obj_index = 0x3A;
    blob.obj_data = 0;
	blob.data_ptr = 0x48FB45AF;
	blob.data_size = 0x9ACA0BBB; 
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	// blob3 -- skype language
	blob.obj_type = 3;
	blob.obj_index = 0x36;
    blob.obj_data = 0;
	blob.data_ptr = (int)LANGUAGE;
	blob.data_size = strlen(LANGUAGE)+1;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // blob4 -- some indexes
    // size and structure of 6 type encoding depends on index number
    blob.obj_type = 6;
	blob.obj_index = 0x33;
    // number of sequences of 4 bytes words.
    blob.obj_data = 5;
	blob.data_ptr = (int)BUF_06_33;
	blob.data_size = sizeof(BUF_06_33)-1;
    buf_len=make_41encode_type6(buf,buf_len,(char *)&blob, 0);

	// blob5 -- our client version
	blob.obj_type = 0x03;
	blob.obj_index = 0x0D;
    blob.obj_data = 0;
	blob.data_ptr = (int)CLIENT_VERSION;
	blob.data_size = strlen(CLIENT_VERSION)+1;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	// blob6 -- some ... hostid2 or unique session garbage data?
	blob.obj_type = 0;
	blob.obj_index = 0x0E;
    blob.obj_data = 0xB24132AE;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // blob7 -- local (remote?) vcard
    blob.obj_type = 4;
	blob.obj_index = 0x13;
    blob.obj_data = 0;
	blob.data_ptr = (int)VCARD;
	blob.data_size = sizeof(VCARD)-1;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	if ( buf_len > buf_limit_len ){
		printf("buffer limit overrun\n");
		exit(1);
	};

	return buf_len;
};


/*

LOGIN PKT

Before AES
Len: 0x00000115
 41 04 00 00 A3 27 00 02 01 03 04 6E 6F 74 6E 6F 
 77 61 67 61 69 6E 70 6C 65 61 73 65 00 04 05 10 
 94 EE DB FF CF BF 02 51 E8 4D DC 48 C3 42 90 12 
 41 07 04 21 80 01 B2 C7 B3 BF C3 0D D7 51 01 4B 
 89 18 1E E3 3C 51 81 5D C6 3B F3 8A 84 DA 9C 81 
 97 55 A9 44 CA CF FE 51 DC F7 05 C1 F4 7D 8D 75 
 86 44 37 3B C2 26 2D B2 C5 BF 02 DC 96 B4 34 3F 
 2C 0E A5 FE AE 92 8C BF 70 8F 7D E6 79 B5 9A 5B 
 42 D8 16 60 EA A1 FB 66 10 3B 61 A2 CE 9C 4E AB 
 3A 63 00 F1 C2 26 BF 1C CB CE 7E AC 66 BB 59 6B 
 16 B4 85 8F F7 B9 85 CB C4 20 BC 67 EA 32 36 56 
 F8 FC FA 8D 42 B5 01 31 9A CA 0B BB 48 FB 45 AF 
 03 36 65 6E 00 06 33 05 AF 8B ED C7 04 B2 90 E3 
 A7 03 F0 A7 A4 01 BD C1 BA A3 0C ED A1 D1 8A 02 
 03 0D 30 2F 36 2E 31 36 2E 30 2E 31 30 2F 2F 00 
 00 0E AE E5 84 92 0B 04 13 1B 65 F1 24 41 7C 03 
 6C 95 01 C0 A8 01 4B E1 08 40 04 17 B0 9C 46 B2 
 41 32 AE E1 08 


===
type6
                06 33 05 
                         AF 8B ED C7 04 B2 90 E3 
 A7 03 F0 A7 A4 01 BD C1 BA A3 0C ED A1 D1 8A 02 
===


{
00-00: A3 13 00 00
00-02: 01 00 00 00
03-04: "notnowagainplease"
04-05: 16 bytes
0000: 94 EE DB FF CF BF 02 51 E8 4D DC 48 C3 42 90 12 | .......Q.M.H.B.. |

}

{
04-21: 128 bytes
0000: B2 C7 B3 BF C3 0D D7 51 01 4B 89 18 1E E3 3C 51 | .......Q.K....<Q |
0010: 81 5D C6 3B F3 8A 84 DA 9C 81 97 55 A9 44 CA CF | .].;.......U.D.. |
0020: FE 51 DC F7 05 C1 F4 7D 8D 75 86 44 37 3B C2 26 | .Q.....}.u.D7;.& |
0030: 2D B2 C5 BF 02 DC 96 B4 34 3F 2C 0E A5 FE AE 92 | -.......4?,..... |
0040: 8C BF 70 8F 7D E6 79 B5 9A 5B 42 D8 16 60 EA A1 | ..p.}.y..[B..`.. |
0050: FB 66 10 3B 61 A2 CE 9C 4E AB 3A 63 00 F1 C2 26 | .f.;a...N.:c...& |
0060: BF 1C CB CE 7E AC 66 BB 59 6B 16 B4 85 8F F7 B9 | ....~.f.Yk...... |
0070: 85 CB C4 20 BC 67 EA 32 36 56 F8 FC FA 8D 42 B5 | ... .g.26V....B. |

01-31: BB 0B CA 9A AF 45 FB 48
03-36: "en"
06-33: AF 45 FB 48, 32 C8 F8 34, F0 13 29 00, BD A0 6E C4, ED 50 54 21
03-0D: "0/6.16.0.10//"
00-0E: AE 32 41 B2
04-13: 27 bytes
0000: 65 F1 24 41 7C 03 6C 95 01 C0 A8 01 4B E1 08 40 | e.$A|.l.....K..@ |
0010: 04 17 B0 9C 46 B2 41 32 AE E1 08                | ....F.A2...      |

}

===
Forming Packet 2
===
	p  = login2;
	p += attach (p, "\x17\x03\x01\x00\x00\x41\x04\x00\x00\x99\x27\x00\x02\x01\x03\x04", 16);
	p += attach (p, user_name, strlen(user_name)+1);
	p += attach (p, "\x04\x05\x10", 3);
	p += MD5_Skype_Password (user_name, password, p);
	p += attach (p, "\x41\x05\x04\x21\x80\x01", 6);
	p += attach (p, public_key, 128);
	p += attach (p, "\x01\x31", 2);
	p += attach (p, hostid1, 8);
	p += attach (p, "\x06\x33\x05", 3);
	p += encode32 (p, hostid2, 5);
	p += attach (p, "\x03\r0/", 4);
	p += attach (p, skype_version, strlen(skype_version));
	p += attach (p, "//\0\x00\x0E", 5);
	p += attach (p, "\x9B\xE7\xAB\xAD\x05", 5);	// should be encode32 (p, something, 1);
	n = (u32) ((u32)p-(u32)login2-5);
===
	
===

*/
