
#define SNODES_MAX 0x1000

struct _snodes_straddr {
    char *ip;
    char *port;
};

struct _slots {
    struct _snodes_straddr snodes[SNODES_MAX];
    u32 snodes_len;
};

