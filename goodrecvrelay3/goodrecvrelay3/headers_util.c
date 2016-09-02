//
// file for slots utilities
//

#include <stdio.h>

#include "short_types.h"

#include "skype/skype_rc4.h"

#include "headers_util.h"

#define HEADERS_MAX 2048

struct _headers_chain headers_chain[HEADERS_MAX];
int headers_chain_len = 0;



int init_headers() {
    headers_chain_len = 0;

	return 0;
};


int add_header_chain(uint remote_header_id, uint local_header_id, uint header_id_crc, int index) {
    int i;

    i = index;

    if (index > headers_chain_len) {
        headers_chain_len = index;
    };

    if (i >= HEADERS_MAX) {
        debuglog("Headers chain too big\n");
        return -1;
    };

    if (remote_header_id != 0x00) {
        headers_chain[i].remote_header_id = remote_header_id;
    };
    if (local_header_id != 0x00) {
        headers_chain[i].local_header_id = local_header_id;
    };
    if (header_id_crc != 0x00) {
        headers_chain[i].header_id_crc = header_id_crc;
    };

	return 0;
};


int get_header_chain(int index, uint *remote_header_id, uint *local_header_id, uint *header_id_crc) {

    *remote_header_id = headers_chain[index].remote_header_id;
    *local_header_id = headers_chain[index].local_header_id;
    *header_id_crc = headers_chain[index].header_id_crc;

	return 0;
};


/*
int update_headers_in_db() {
    int i;

    for (i=0;i<=headers_chain_len;i++) {
        debuglog("\nChain #%d\n", i);
        debuglog("00-09: %08X\n", _bswap32(headers_chain[i].remote_header_id));
        debuglog("00-0A: %08X\n", _bswap32(headers_chain[i].local_header_id));
        debuglog("00-15: %08X\n", _bswap32(headers_chain[i].header_id_crc));

    };
    
    return 0;
};
*/


int dump_headers() {
    int i;

    for (i=0;i<=headers_chain_len;i++) {
        debuglog("\nChain #%d\n", i);
        debuglog("00-09: %08X\n", _bswap32(headers_chain[i].remote_header_id));
        debuglog("00-0A: %08X\n", _bswap32(headers_chain[i].local_header_id));
        debuglog("00-15: %08X\n", _bswap32(headers_chain[i].header_id_crc));
    };
    
    return 0;
};


int count_cmd15_headers(unsigned int remote_start_header) {
    int i;
    int count;

    debuglog("\nNeed recv:\n");

    count = 0;
    for (i=0;i<=headers_chain_len;i++) {

        if (headers_chain[i].remote_header_id == headers_chain[i].local_header_id) {
            if (remote_start_header != headers_chain[i].remote_header_id) {
                count++;
                debuglog("Count: %d\n", count);
                debuglog("00-09: %08X\n", _bswap32(headers_chain[i].remote_header_id));
                debuglog("00-0A: %08X\n", _bswap32(headers_chain[i].local_header_id));
                debuglog("00-15: %08X\n", _bswap32(headers_chain[i].header_id_crc));
            };
        };

    };
    
    return count;
};


int count_cmd15_headers2(unsigned int remote_start_header, unsigned int local_last_synced,
                         unsigned int *remote_first, unsigned int *remote_last) {
    int i;
    int count;
    unsigned int remote_last_synced;


    // find remote last synced in cmd13recv at first
    // use our last synced local_header_id for this

    remote_last_synced = 0;
    for (i=0;i<=headers_chain_len;i++) {
        if (headers_chain[i].remote_header_id == local_last_synced) {
            remote_last_synced = headers_chain[i].local_header_id;
        };
    };

    debuglog("local_last_synced 0x%08X\n", _bswap32(local_last_synced));
    debuglog("find remote_last_synced 0x%08X\n", _bswap32(remote_last_synced));

    debuglog("\nNeed recv:\n");

    count = 0;
    for (i=0;i<=headers_chain_len;i++) {

        if (headers_chain[i].remote_header_id == headers_chain[i].local_header_id) {
            if (headers_chain[i].remote_header_id > remote_last_synced) {
                if (count == 0) {
                    *remote_first = headers_chain[i].remote_header_id;
                };
                count++;
                debuglog("Count: %d\n", count);
                debuglog("00-09: %08X (remote header, but for us it is local_header)\n", _bswap32(headers_chain[i].remote_header_id));
                debuglog("00-0A: %08X (local_header, but for us it is remote_header)\n", _bswap32(headers_chain[i].local_header_id));
                debuglog("00-15: %08X\n", _bswap32(headers_chain[i].header_id_crc));
            };
        };

    };

    *remote_last = *remote_first + count - 1;
    
    return count;
};


int clear_headers() {
    int i;

    for (i=0;i<=headers_chain_len;i++) {
        headers_chain[i].remote_header_id = 0x00;
        headers_chain[i].local_header_id = 0x00;
        headers_chain[i].header_id_crc = 0x00;
    };

    headers_chain_len = 0;

	return 0;
};

