//
// parse returned data
//

#include <stdio.h>
#include <stdlib.h>

#include "short_types.h"

#include "relays_util.h"

extern struct _relays relays;


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

    debuglog("Looking for 02-11 (supernode ip:port) blob...\n");
    ret = main_unpack_checkblob(membuf, membuf_len, 0x02, 0x11);
    if (ret) {
        debuglog("BLOB found!\n");

        pktnum = 0;
        i = 0;    
        do {
            ret = main_unpack_getobj02ip(membuf, membuf_len, &ip, &port, 0x02, 0x11, pktnum, i);
            if (ret) {
                debuglog("%u.%u.%u.%u:%u\n", ip>>24, (ip>>16)&0xFF, (ip>>8)&0xFF, ip&0xFF, port);
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

    debuglog("Looking for 00-03 blob...\n");
    ret = main_unpack_checkblob(buf, buf_len, 0x00, 0x03);
    if (ret == 1){
        debuglog("BLOB found!\n");
        main_unpack_getobj00(buf, buf_len, &data_int, 0x00, 0x03);
        debuglog("00-03 (Conn ID): 0x%08X\n", data_int);
        *conn_id = data_int;
    } else {
        debuglog("not found blob 00-03 in relay answer\n");
    };

    return 0;
};

