//
// file for slots utilities
//

#include <stdio.h>

#include "skype/skype_rc4.h"

#include "short_types.h"

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

