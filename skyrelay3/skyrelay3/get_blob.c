//
// parse returned data
//

#include <stdio.h>
#include <stdlib.h>

#include "short_types.h"

#include "relays_util.h"

extern struct _relays relays;

/*

// get version string

{
00-39: CE 90 00 00
00-03: 1B 50 00 00
04-01: 29 bytes
0000: 7E 0D 88 A6 2C 69 F9 17 01 00 00 00 00 00 00 9D | ~...,i.......... |
0010: 37 82 AE 9C 51 00 00 00 00 00 00 08 11          | 7...Q........    |

01-09: 14 31 21 42 3B 09 41 30
00-1B: 05 00 00 00
05-07: {
02-08: 93.228.74.220:30204
00-03: 21 00 00 00
00-10: 1E 00 00 00
00-32: 01 00 00 00
}
00-38: 00 00 00 00
00-21: 00 00 00 00
00-29: 11 00 00 00
00-26: 03 00 00 00
00-2A: 34 00 00 00
00-31: 03 00 00 00
03-2B: "0/7.8.64.102//"
00-16: 01 00 00 00
00-1A: 01 00 00 00
00-1D: 86 00 00 00
00-1E: 00 00 00 00
04-05: 411 bytes
0000: 00 00 01 04 00 00 00 01 07 AC AA DB B0 63 7B F9 | .............c{. |
0010: 7C 0A BB DC 3A E7 54 20 61 89 8C 4F D8 CE 8B FB | |...:.T a..O.... |
0020: FD 6F 32 14 25 D2 6C 3F B8 90 FE 58 5E 97 26 71 | .o2.%.l?...X^.&q |
0030: 64 EA 7C FE 6E E4 0B 43 DE 63 21 98 D7 AB DE 02 | d.|.n..C.c!..... |
0040: 45 59 AD 58 ED C8 C1 50 FA D7 4C 79 54 37 3A F2 | EY.X...P..LyT7:. |
0050: 69 32 4F 84 2D 43 5E D3 FA ED 9F A5 C7 24 27 2E | i2O.-C^......$'. |
0060: EC 8E C4 28 40 E2 3A 80 EB 43 B9 7D 40 B9 83 44 | ...(@.:..C.}@..D |
0070: 0C F1 34 EB BF C7 6E 19 8A 7D 3F 8C D4 A0 D2 7C | ..4...n..}?....| |
0080: 19 F3 8B DF 9F 7E 91 27 F5 A8 53 BF 57 63 CF 4A | .....~.'..S.Wc.J |
0090: 63 2D B6 BA 42 ED F1 4D F5 8A 1F 18 2C 6C 96 6C | c-..B..M....,l.l |
00A0: C0 C0 B2 71 C2 38 14 49 D4 08 AA C8 86 36 22 6B | ...q.8.I.....6"k |
00B0: 84 50 7F 5F 05 96 3D 7C A5 2C 9F ED 42 12 71 BF | .P._..=|.,..B.q. |
00C0: A5 57 D3 49 80 06 C7 48 D7 35 93 27 3D 62 59 96 | .W.I...H.5.'=bY. |
00D0: FA 9B B5 60 86 91 E9 24 26 45 53 79 DD A3 B8 E2 | ...`...$&ESy.... |
00E0: CF 5C 77 91 07 8A 6E A5 D0 BC 1C F0 F2 84 98 EA | .\w...n......... |
00F0: 0F 63 88 AD F6 48 F5 92 0F 42 6C 9A CF 02 14 C1 | .c...H...Bl..... |
0100: 1F C5 17 37 56 67 76 78 1F 31 F0 02 70 21 51 D3 | ...7Vgvx.1..p!Q. |
0110: 7E 86 78 56 F1 C1 00 9A 7C 55 29 19 B9 CB D7 5D | ~.xV....|U)....] |
0120: CF DA 2B B2 A6 49 AA 54 DE 8E DF 89 95 3C 8B 9B | ..+..I.T.....<.. |
0130: 65 B8 A3 45 D5 9D F6 6B 63 AB 70 0E 29 B9 DA F5 | e..E...kc.p.)... |
0140: 0E 74 54 89 E8 A6 E0 EE 7D 4B 2A 4F 02 96 31 F6 | .tT.....}K*O..1. |
0150: F2 00 29 46 15 4E 78 EB F3 C3 AC 7A 76 53 8E 82 | ..)F.Nx....zvS.. |
0160: 6C 76 FB 2C 92 BA 97 33 24 21 03 6E 05 74 4B 49 | lv.,...3$!.n.tKI |
0170: BB 83 4C 89 6E EA 61 B9 4E 5F 27 22 36 59 B8 DE | ..L.n.a.N_'"6Y.. |
0180: ED B8 CF 5D AB 6E 80 C2 00 00 00 00 00 9D 37 82 | ...].n........7. |
0190: AE 9C 51 00 00 00 00 00 00 08 11                | ..Q........      |

00-15: 02 00 00 00
04-0A: 128 bytes
0000: 12 A8 9E BD 19 19 EB E7 64 25 CB C7 51 83 FD 88 | ........d%..Q... |
0010: 4C 8F 8E A7 52 DD 55 60 97 A8 A0 BA 7D 71 1B 28 | L...R.U`....}q.( |
0020: A3 87 45 34 51 09 03 45 1B 7F 5C 9F 4D 73 F3 90 | ..E4Q..E..\.Ms.. |
0030: E0 E6 B9 01 3A DB 2E 68 BD 6E 9E F0 44 A3 AD 8D | ....:..h.n..D... |
0040: BF 9A 8F F8 99 C7 13 BD C3 64 E1 D9 F7 FD 11 DE | .........d...... |
0050: F0 89 E9 B9 51 01 FB A6 BD B0 98 D1 7F DF 7E 78 | ....Q.........~x |
0060: 86 49 24 96 1F 2D 5F D7 67 4F FF 74 81 E3 2B 01 | .I$..-_.gO.t..+. |
0070: A5 8D FD EA 97 28 4C 16 83 C3 EF 27 57 EA 4C 2B | .....(L....'W.L+ |

}

*/


//
// 03-2B remote version blob
//
int get_03_2B_blob(char *membuf, int membuf_len, char *output){
	int ret;
    u8 remote_version[0x100];
    int remote_version_len;

    remote_version_len = 0;

	printf("Looking for 03-2B (contact name) blob...\n");
	ret = main_unpack_checkblob(membuf, membuf_len, 0x03, 0x2B);
	if (ret == 1) {
		printf("BLOB found!\n");
		ret = main_unpack_getbuf (membuf, membuf_len, remote_version, &remote_version_len, 0x03, 0x2B);
        //remote_version[remote_version_len]=0;
		printf("remote_version: %s\n",remote_version);
		printf("remote_version_len: %d bytes\n", remote_version_len);
        memcpy(output, remote_version, remote_version_len);
	};

	return remote_version_len;
};


/*
{
02-11: 178.168.129.245:21595
05-1A: {
00-00: 34 00 00 00
00-02: 00 00 00 00
00-03: 00 00 00 00
00-04: 18 00 00 00
00-0A: 64 00 00 00
03-10: "BY"
00-12: 89 00 00 00
00-21: 03 00 00 00
}
02-11: 178.168.45.16:41292
05-1A: {
00-00: 34 00 00 00
00-02: 22 00 00 00
00-03: 05 00 00 00
00-04: 4F 00 00 00
00-0A: 64 00 00 00
03-10: "IE"
00-11: 00 00 00 00
00-12: 91 00 00 00
00-21: 03 00 00 00
}
}
*/

int get_02_11_blob(char *membuf, int membuf_len) {
    int ret;
    u32 ip;
    u32 port;
    u32 slot;
    int size;
    int i;
    int pktnum;
    FILE *fp;
    int total;

    relays.relays_len = 0;

    printf("Looking for 02-11 (supernode ip:port) blob...\n");
    ret = main_unpack_checkblob(membuf, membuf_len, 0x02, 0x11);
    if (ret) {
        printf("BLOB found!\n");

        pktnum = 0;
        i = 0;    
        do {
            ret = main_unpack_getobj02ip(membuf, membuf_len, &ip, &port, 0x02, 0x11, pktnum, i);
            if (ret) {
                printf("%u.%u.%u.%u:%u\n", ip>>24, (ip>>16)&0xFF, (ip>>8)&0xFF, ip&0xFF, port);
                relays.relay[i].ip = ip;
                relays.relay[i].port = port;
                relays.relays_len++;
            };
            i++;
        } while (ret);
    };

    return 0;
};


//
// 00-03 (get connid) 
//
int get_00_03_blob(u8 *buf, int buf_len, int *conn_id){
    int ret;
    unsigned long data_int;
    data_int = 0;

    printf("Looking for 00-03 blob...\n");
    ret = main_unpack_checkblob(buf, buf_len, 0x00, 0x03);
    if (ret == 1){
        printf("BLOB found!\n");
        main_unpack_getobj00(buf, buf_len, &data_int, 0x00, 0x03);
        printf("00-03 (Conn ID): 0x%08X\n", data_int);
        *conn_id = data_int;
    } else {
        printf("not found blob 00-03 in relay answer\n");
    };

    return 0;
};

