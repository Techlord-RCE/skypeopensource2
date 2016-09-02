//
// setup pkt 2
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


extern u8 CREDENTIALS188[0x189];
extern uint CREDENTIALS188_LEN;

u8 REMOTE_AUTHORIZED188[0x189];
extern uint REMOTE_AUTHORIZED188_LEN;


extern u8 MSG_TEXT[0x100];
extern u8 CHAT_STRING[0x100];
extern u8 CHAT_PEERS[0x100];
extern u8 CREDENTIALS[0x105];
extern uint CREDENTIALS_LEN;
extern u8 NEWBLK[0x1000];
extern uint NEWBLK_LEN;
extern u8 REMOTE_NAME[0x100];


extern u8 CHALLENGE_RESPONSE[0x80];
extern u8 LOCAL_NONCE[0x80];
extern u8 LOCAL_UIC[0x189];

extern uint BLOB_0_2;


int encode41_setup2pkt(char *buf, int buf_limit_len){
	struct blob_s blob;
	uint session_id;
	uint session_cmd;
	int buf_len;

	int blob_count;

	//session_id=0x45EF;
    session_id=0x028D93;

	session_cmd=0x45;

	memset(buf,0,sizeof(buf));
    buf_len=0;

	// 0x0C
	blob_count = 12;

    buf_len=make_41cmdencode(buf, buf_len, blob_count, session_id, session_cmd, 0);


    // blob1
    blob.obj_type = 0;
	blob.obj_index = 0x16;
    blob.obj_data = 1;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // blob2
    blob.obj_type = 0;
	blob.obj_index = 0x1A;
    blob.obj_data = 1;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // blob3
    blob.obj_type = 0;
	blob.obj_index = 0x1D;
	blob.obj_data = 0xFA;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // blob4
    blob.obj_type = 0;
	blob.obj_index = 0x1E;
    blob.obj_data = 0;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);
	

	// blob5 -- our real internet ip
    blob.obj_type = 0;
	blob.obj_index = 2;
	blob.obj_data = 0xB2412C15;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // blob6 -- ALLOC1 credentials ciphered
    blob.obj_type = 4;
	blob.obj_index = 5;
    blob.obj_data = 0;
	blob.data_ptr = (int)CREDENTIALS188;
	blob.data_size = CREDENTIALS188_LEN;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // blob7 -- some flag
    blob.obj_type = 0;
	blob.obj_index = 0x15;
    blob.obj_data = 2;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // blob8 -- ALLOC2 challenge_response
    blob.obj_type = 4;
	blob.obj_index = 0x0A;
    blob.obj_data = 0;
	blob.data_ptr = (int)CHALLENGE_RESPONSE;
	blob.data_size = sizeof(CHALLENGE_RESPONSE);
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // hz -- blob9
    blob.obj_type = 0;
	blob.obj_index = 0x19;
    blob.obj_data = 1;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);
	
    // blob10 -- ALLOC3 aes nonce, encrypted by rsa public key (for aes key)
    blob.obj_type = 4;
	blob.obj_index = 0x06;
    blob.obj_data = 0;
	blob.data_ptr = (int)LOCAL_NONCE;
	blob.data_size = sizeof(LOCAL_NONCE);
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // blob11 -- ALLOC4 
    blob.obj_type = 4;
	blob.obj_index = 0x11;
    blob.obj_data = 0;
	blob.data_ptr = (int)REMOTE_AUTHORIZED188;
	blob.data_size = REMOTE_AUTHORIZED188_LEN;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // hz -- blob12
    blob.obj_type = 0;
	blob.obj_index = 0x14;
    blob.obj_data = 0;
	blob.data_ptr = 0;
	blob.data_size = 0;
    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	if ( buf_len > buf_limit_len ){
		debuglog("buffer limit overrun\n");
		return -1;
	};

	return buf_len;
};


/*

===
20:32:11.674 T#1348 Logger AES dump from 00914C97 len 445
20:32:11.674 T#1348 Before: 
20:32:11.674 T#1348 93 8D 02 45 41 0C 00 16 01 00 1A 01 00 1D FA 01 
20:32:11.674 T#1348 00 1E 00 00 02 95 D8 84 92 0B 04 05 88 03 00 00 
20:32:11.674 T#1348 01 04 00 00 00 01 A7 CF DF F5 A9 69 80 2C 56 12 
20:32:11.674 T#1348 D5 8B 4B B1 6A 51 0B F4 E1 69 47 96 89 2D 82 A2 
20:32:11.674 T#1348 16 B7 19 C9 52 DF 08 84 0D 28 04 0F 10 6F 07 D4 
20:32:11.674 T#1348 FF 3E 64 80 34 36 DC 25 5F 79 F1 7F 1C 4C 90 9C 
20:32:11.674 T#1348 03 E2 EF 9D B9 C6 D9 52 55 D4 C0 FE 31 6E 08 EA 
20:32:11.674 T#1348 FA C9 61 BB F8 DA F7 2E 8A 13 16 B2 12 7E 17 38 
20:32:11.674 T#1348 D7 13 2E 85 1D 27 63 71 DD 48 A9 95 37 F6 FE 62 
20:32:11.674 T#1348 76 31 F8 0E 5E 4B 1A 8C C2 F4 14 80 5E 96 1C CB 
20:32:11.674 T#1348 81 E7 DC 5A F5 E7 D8 6D E7 9F F2 AD 77 A1 E1 A4 
20:32:11.674 T#1348 03 CF 57 41 C6 61 82 D8 BF 24 7A 1F C4 23 08 DC 
20:32:11.674 T#1348 C2 5A 63 79 95 FF 0B 3E 1E F8 7A 6C 49 05 00 45 
20:32:11.674 T#1348 5E DD AB 9F 19 F6 50 D1 4A B9 02 92 C5 62 6E 27 
20:32:11.674 T#1348 44 DC 68 06 09 FD 1D 6E C1 C0 0F 3D 90 E4 1A F9 
20:32:11.674 T#1348 DE 46 5B 27 B6 9F 48 AC B4 1A 95 92 8C 7D E2 9D 
20:32:11.674 T#1348 A3 A7 C7 06 95 2A FC D3 86 C3 46 4E 7E 9F F8 A6 
20:32:11.674 T#1348 2C E9 5D 94 FC 95 CC C0 83 84 C0 40 35 DD A0 72 
20:32:11.674 T#1348 6B 78 7C 26 3E 68 D1 95 D9 B8 BD C7 22 63 43 DD 
20:32:11.674 T#1348 7F 70 B3 23 61 7D 13 59 3B D2 12 8D 8A 9F A5 B0 
20:32:11.674 T#1348 6F 73 B7 2A 71 A6 93 47 E1 07 59 E6 25 68 E5 C5 
20:32:11.674 T#1348 42 0C 4D 68 6B 8B D8 D6 28 D0 1D 1C F7 F9 63 66 
20:32:11.674 T#1348 9C A6 57 B5 1F 8B 4B 40 D8 A7 AB 93 73 96 00 0C 
20:32:11.674 T#1348 E8 6F 4A AB 3A EA E7 94 3B 75 18 6B 21 88 D9 A7 
20:32:11.674 T#1348 90 BB 9A 10 25 ED F7 A2 88 AE 48 4C 24 A0 F6 39 
20:32:11.674 T#1348 D3 0E 67 A9 78 74 FA A6 34 F3 7C 97 52 53 7F 49 
20:32:11.674 T#1348 F1 9D F5 BA E8 5D 00 15 02 04 0A 80 01 46 DF A0 
20:32:11.674 T#1348 B8 95 7A 3C F9 83 3E 8E B0 F4 46 BD 98 64 E4 7C 
20:32:11.674 T#1348 E9 DB A9 0D EE 71 DA 92 4E 6C 9D D6 AD 79 A7 60 
20:32:11.674 T#1348 23 25 25 D3 7A C9 4F C0 44 D0 F9 68 8E F1 A0 98 
20:32:11.674 T#1348 5C 31 38 8B 4F DB 2D 8E 4D AC AF FB 2D 2E 0B C8 
20:32:11.674 T#1348 C2 C9 61 74 A5 A3 49 C3 6E 7E A4 3F 35 9C 89 EB 
20:32:11.674 T#1348 21 61 07 A5 D0 EE 65 01 B3 84 55 F3 ED E2 46 BE 
20:32:11.674 T#1348 B2 77 15 78 76 82 CD CD 63 3D A7 55 38 19 93 1E 
20:32:11.674 T#1348 ED 77 2F 82 B5 DC 7F 7B 34 66 28 EF 64 00 19 01 
20:32:11.674 T#1348 04 06 80 01 9F 72 7E 7E 32 3C ED DD AD CB A3 C5 
20:32:11.674 T#1348 10 57 4A F0 01 BA DD 60 95 36 CF 72 1F 63 87 23 
20:32:11.674 T#1348 9D C4 E9 89 06 C7 26 C4 D1 7D 4A 57 C6 26 9B 09 
20:32:11.674 T#1348 EC 61 64 D1 38 0E 07 9A 32 EE 19 05 C2 39 CA 6C 
20:32:11.674 T#1348 EF 76 65 FA 91 96 4E 2A E1 A6 65 4B F0 75 94 D2 
20:32:11.674 T#1348 95 35 FA 9B 24 7F 8B 04 70 DC D1 83 32 5C F3 57 
20:32:11.674 T#1348 2D E0 97 16 7D 6B D1 A8 99 4C B7 5D 2F D3 14 93 
20:32:11.674 T#1348 FC D7 2D D8 13 83 5D 57 C8 51 3D D1 A0 C1 D5 D7 
20:32:11.674 T#1348 B9 E8 9A F8 04 11 88 03 00 00 01 04 00 00 00 01 
20:32:11.674 T#1348 94 8E D8 A1 58 6D 7A 36 15 C8 FA 6C EA 81 44 92 
20:32:11.674 T#1348 3D D8 C6 82 B2 35 7C 8E 7A 73 3F C5 90 B6 AD EF 
20:32:11.674 T#1348 AE 9B 89 20 D5 FF 6F 68 B3 AC DA 10 0B B0 2B 45 
20:32:11.674 T#1348 EA 60 77 8D 98 3E 25 64 F6 01 79 A8 DA 97 9D B6 
20:32:11.674 T#1348 54 49 15 A7 A1 32 40 96 5A C4 8D 6E 9A 0C 40 84 
20:32:11.674 T#1348 AB E2 1F 61 E5 9A 65 5B 32 85 9A 03 5C BF 33 16 
20:32:11.674 T#1348 D2 EB 14 B6 B3 8D DC 1A 73 A0 AC 0C B8 4C E0 8C 
20:32:11.674 T#1348 49 EE 55 88 D1 DA 38 69 05 3D BA 12 77 6F 26 BA 
20:32:11.674 T#1348 6F 16 70 95 FD 02 19 E3 99 A5 7C 91 5F D4 E6 45 
20:32:11.674 T#1348 55 88 79 8A 30 40 D9 9A 15 E8 00 C8 EA 49 54 C0 
20:32:11.674 T#1348 C0 B5 34 E0 78 10 45 91 90 10 D2 1A 04 91 F7 45 
20:32:11.674 T#1348 55 A3 9D D8 6C A7 A0 59 EF 3F 5C 8C 36 19 C0 90 
20:32:11.674 T#1348 C7 3A 53 78 89 A0 4F AB 9B 73 CC 01 B4 29 BC 4C 
20:32:11.674 T#1348 9E CF 47 0D FB A8 B8 47 9B 3F 74 AC A6 7D FF E3 
20:32:11.674 T#1348 D9 4E FB 0D B1 1C AF 5A B8 DC F1 0B EB 0A 40 70 
20:32:11.674 T#1348 87 51 78 E1 7D F6 79 8B 20 52 8B CF DA 60 36 58 
20:32:11.674 T#1348 5E 1D 40 4A 21 65 25 F5 1C 5A BE D2 AA 37 8A D6 
20:32:11.674 T#1348 48 1C 0C 96 3D 92 33 F1 A8 6D 31 35 28 B0 E4 80 
20:32:11.674 T#1348 D7 79 2A 4C B3 97 63 53 72 6B 61 4C F1 96 D8 9A 
20:32:11.674 T#1348 24 F5 54 4A C5 A0 2C 4C 7A E4 78 E2 B9 B2 22 5B 
20:32:11.674 T#1348 FF 08 8E B5 16 59 B0 17 C1 E6 0B 44 92 F8 F6 DA 
20:32:11.674 T#1348 83 6B C0 03 E4 1D 76 FF 6A BC 3D 30 B0 1D 47 09 
20:32:11.674 T#1348 D8 20 55 79 AD 40 7C 37 0C 5F 30 AE 54 05 E9 3D 
20:32:11.674 T#1348 E4 2D 5E E1 89 A9 61 DA A0 FD 89 F1 1B 36 FF 9A 
20:32:11.674 T#1348 00 14 00 F8 07 
===
PARAM send0002
===
{
00-16: 01 00 00 00
00-1A: 01 00 00 00
00-1D: FA 00 00 00
00-1E: 00 00 00 00
00-02: 15 2C 41 B2
04-05: 392 bytes
0000: 00 00 01 04 00 00 00 01 A7 CF DF F5 A9 69 80 2C | .............i., |
0010: 56 12 D5 8B 4B B1 6A 51 0B F4 E1 69 47 96 89 2D | V...K.jQ...iG..- |
0020: 82 A2 16 B7 19 C9 52 DF 08 84 0D 28 04 0F 10 6F | ......R....(...o |
0030: 07 D4 FF 3E 64 80 34 36 DC 25 5F 79 F1 7F 1C 4C | ...>d.46.%_y...L |
0040: 90 9C 03 E2 EF 9D B9 C6 D9 52 55 D4 C0 FE 31 6E | .........RU...1n |
0050: 08 EA FA C9 61 BB F8 DA F7 2E 8A 13 16 B2 12 7E | ....a..........~ |
0060: 17 38 D7 13 2E 85 1D 27 63 71 DD 48 A9 95 37 F6 | .8.....'cq.H..7. |
0070: FE 62 76 31 F8 0E 5E 4B 1A 8C C2 F4 14 80 5E 96 | .bv1..^K......^. |
0080: 1C CB 81 E7 DC 5A F5 E7 D8 6D E7 9F F2 AD 77 A1 | .....Z...m....w. |
0090: E1 A4 03 CF 57 41 C6 61 82 D8 BF 24 7A 1F C4 23 | ....WA.a...$z..# |
00A0: 08 DC C2 5A 63 79 95 FF 0B 3E 1E F8 7A 6C 49 05 | ...Zcy...>..zlI. |
00B0: 00 45 5E DD AB 9F 19 F6 50 D1 4A B9 02 92 C5 62 | .E^.....P.J....b |
00C0: 6E 27 44 DC 68 06 09 FD 1D 6E C1 C0 0F 3D 90 E4 | n'D.h....n...=.. |
00D0: 1A F9 DE 46 5B 27 B6 9F 48 AC B4 1A 95 92 8C 7D | ...F['..H......} |
00E0: E2 9D A3 A7 C7 06 95 2A FC D3 86 C3 46 4E 7E 9F | .......*....FN~. |
00F0: F8 A6 2C E9 5D 94 FC 95 CC C0 83 84 C0 40 35 DD | ..,.]........@5. |
0100: A0 72 6B 78 7C 26 3E 68 D1 95 D9 B8 BD C7 22 63 | .rkx|&>h......"c |
0110: 43 DD 7F 70 B3 23 61 7D 13 59 3B D2 12 8D 8A 9F | C..p.#a}.Y;..... |
0120: A5 B0 6F 73 B7 2A 71 A6 93 47 E1 07 59 E6 25 68 | ..os.*q..G..Y.%h |
0130: E5 C5 42 0C 4D 68 6B 8B D8 D6 28 D0 1D 1C F7 F9 | ..B.Mhk...(..... |
0140: 63 66 9C A6 57 B5 1F 8B 4B 40 D8 A7 AB 93 73 96 | cf..W...K@....s. |
0150: 00 0C E8 6F 4A AB 3A EA E7 94 3B 75 18 6B 21 88 | ...oJ.:...;u.k!. |
0160: D9 A7 90 BB 9A 10 25 ED F7 A2 88 AE 48 4C 24 A0 | ......%.....HL$. |
0170: F6 39 D3 0E 67 A9 78 74 FA A6 34 F3 7C 97 52 53 | .9..g.xt..4.|.RS |
0180: 7F 49 F1 9D F5 BA E8 5D                         | .I.....]         |

00-15: 02 00 00 00
04-0A: 128 bytes
0000: 46 DF A0 B8 95 7A 3C F9 83 3E 8E B0 F4 46 BD 98 | F....z<..>...F.. |
0010: 64 E4 7C E9 DB A9 0D EE 71 DA 92 4E 6C 9D D6 AD | d.|.....q..Nl... |
0020: 79 A7 60 23 25 25 D3 7A C9 4F C0 44 D0 F9 68 8E | y.`#%%.z.O.D..h. |
0030: F1 A0 98 5C 31 38 8B 4F DB 2D 8E 4D AC AF FB 2D | ...\18.O.-.M...- |
0040: 2E 0B C8 C2 C9 61 74 A5 A3 49 C3 6E 7E A4 3F 35 | .....at..I.n~.?5 |
0050: 9C 89 EB 21 61 07 A5 D0 EE 65 01 B3 84 55 F3 ED | ...!a....e...U.. |
0060: E2 46 BE B2 77 15 78 76 82 CD CD 63 3D A7 55 38 | .F..w.xv...c=.U8 |
0070: 19 93 1E ED 77 2F 82 B5 DC 7F 7B 34 66 28 EF 64 | ....w/....{4f(.d |

00-19: 01 00 00 00
04-06: 128 bytes
0000: 9F 72 7E 7E 32 3C ED DD AD CB A3 C5 10 57 4A F0 | .r~~2<.......WJ. |
0010: 01 BA DD 60 95 36 CF 72 1F 63 87 23 9D C4 E9 89 | ...`.6.r.c.#.... |
0020: 06 C7 26 C4 D1 7D 4A 57 C6 26 9B 09 EC 61 64 D1 | ..&..}JW.&...ad. |
0030: 38 0E 07 9A 32 EE 19 05 C2 39 CA 6C EF 76 65 FA | 8...2....9.l.ve. |
0040: 91 96 4E 2A E1 A6 65 4B F0 75 94 D2 95 35 FA 9B | ..N*..eK.u...5.. |
0050: 24 7F 8B 04 70 DC D1 83 32 5C F3 57 2D E0 97 16 | $...p...2\.W-... |
0060: 7D 6B D1 A8 99 4C B7 5D 2F D3 14 93 FC D7 2D D8 | }k...L.]/.....-. |
0070: 13 83 5D 57 C8 51 3D D1 A0 C1 D5 D7 B9 E8 9A F8 | ..]W.Q=......... |

04-11: 392 bytes
0000: 00 00 01 04 00 00 00 01 94 8E D8 A1 58 6D 7A 36 | ............Xmz6 |
0010: 15 C8 FA 6C EA 81 44 92 3D D8 C6 82 B2 35 7C 8E | ...l..D.=....5|. |
0020: 7A 73 3F C5 90 B6 AD EF AE 9B 89 20 D5 FF 6F 68 | zs?........ ..oh |
0030: B3 AC DA 10 0B B0 2B 45 EA 60 77 8D 98 3E 25 64 | ......+E.`w..>%d |
0040: F6 01 79 A8 DA 97 9D B6 54 49 15 A7 A1 32 40 96 | ..y.....TI...2@. |
0050: 5A C4 8D 6E 9A 0C 40 84 AB E2 1F 61 E5 9A 65 5B | Z..n..@....a..e[ |
0060: 32 85 9A 03 5C BF 33 16 D2 EB 14 B6 B3 8D DC 1A | 2...\.3......... |
0070: 73 A0 AC 0C B8 4C E0 8C 49 EE 55 88 D1 DA 38 69 | s....L..I.U...8i |
0080: 05 3D BA 12 77 6F 26 BA 6F 16 70 95 FD 02 19 E3 | .=..wo&.o.p..... |
0090: 99 A5 7C 91 5F D4 E6 45 55 88 79 8A 30 40 D9 9A | ..|._..EU.y.0@.. |
00A0: 15 E8 00 C8 EA 49 54 C0 C0 B5 34 E0 78 10 45 91 | .....IT...4.x.E. |
00B0: 90 10 D2 1A 04 91 F7 45 55 A3 9D D8 6C A7 A0 59 | .......EU...l..Y |
00C0: EF 3F 5C 8C 36 19 C0 90 C7 3A 53 78 89 A0 4F AB | .?\.6....:Sx..O. |
00D0: 9B 73 CC 01 B4 29 BC 4C 9E CF 47 0D FB A8 B8 47 | .s...).L..G....G |
00E0: 9B 3F 74 AC A6 7D FF E3 D9 4E FB 0D B1 1C AF 5A | .?t..}...N.....Z |
00F0: B8 DC F1 0B EB 0A 40 70 87 51 78 E1 7D F6 79 8B | ......@p.Qx.}.y. |
0100: 20 52 8B CF DA 60 36 58 5E 1D 40 4A 21 65 25 F5 |  R...`6X^.@J!e%. |
0110: 1C 5A BE D2 AA 37 8A D6 48 1C 0C 96 3D 92 33 F1 | .Z...7..H...=.3. |
0120: A8 6D 31 35 28 B0 E4 80 D7 79 2A 4C B3 97 63 53 | .m15(....y*L..cS |
0130: 72 6B 61 4C F1 96 D8 9A 24 F5 54 4A C5 A0 2C 4C | rkaL....$.TJ..,L |
0140: 7A E4 78 E2 B9 B2 22 5B FF 08 8E B5 16 59 B0 17 | z.x..."[.....Y.. |
0150: C1 E6 0B 44 92 F8 F6 DA 83 6B C0 03 E4 1D 76 FF | ...D.....k....v. |
0160: 6A BC 3D 30 B0 1D 47 09 D8 20 55 79 AD 40 7C 37 | j.=0..G.. Uy.@|7 |
0170: 0C 5F 30 AE 54 05 E9 3D E4 2D 5E E1 89 A9 61 DA | ._0.T..=.-^...a. |
0180: A0 FD 89 F1 1B 36 FF 9A                         | .....6..         |

00-14: 00 00 00 00
}
===

*/

