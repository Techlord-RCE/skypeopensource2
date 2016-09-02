
#include "short_types.h"
//
#define SNODES_MAX 0x100

struct _relay_addr {
    u32 ip;
    u32 port;
};

struct _relays {
    struct _relay_addr relay[SNODES_MAX];
    u32 relays_len;
};

//struct _relays relays;
//
