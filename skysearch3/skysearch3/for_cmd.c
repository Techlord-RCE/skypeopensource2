// skysearch3.c -- search given skype username on skype network
//


#include <stdio.h>
#include <stdlib.h>

#include <string.h>  

#include <time.h>
#include <errno.h>  

#include "miracl_lib/miracl.h"

#include "short_types.h"

#include "slots_util.h"


int main_test () {
	int ret;
    int argc;
    char *argv[10];
    char myip[1000];

	argc = 1;
    argv[0] = strdup("xot_iam");

	ret = main_skysearch_getslots(argc, argv, myip);

	printf("Run Done.\n");

};

int main(int argc, char* argv[]) {

    main_from_cmd(argc, argv);

    //main_from_cmd(argc, argv);

    return 0;
};


//
// Main (for call from cmd)
//
//ip of supernode, from skype.log "probe accept"
int main_from_cmd(int argc, char* argv[]) {
    char *destip;
    u16 destport;
    char *user;
    char *skypeuser;
    char our_public_ip[128];
    u32 userslot;
    int ret;
    u32 i;
    int n_argc;
    int n_argv[0x10];
    
    srand( time(NULL) );

    sockets_init();

    if (argc == 1){
        printf("usage: <skypenames>\n");
        return -1;
    };

    skypeuser=strdup(argv[1]);

    n_argc = 0;
    for(i=1; i<argc; i++) {
        user = argv[i];
        userslot=slot_find(user);
        printf("%s slot: #%d (0x%08X)\n", user, userslot, userslot);
        n_argv[n_argc] = userslot;
        n_argc++;
    };
    printf("\n");

    // get and fill slots
    main_get_slotinfo(n_argc, n_argv);


    /*
    userslot=slot_find(skypeuser);
    printf("slot: #%d (0x%08X)\n",userslot,userslot);
    printf("nodes in slot: %d\n",slots[userslot].snodes_len);

    destip = "213.199.179.160";
    destport = 40030;
    ret=snode_udp_reqsearch(destip,destport,our_public_ip,skypeuser);
    */

    init_vcard_array();

    load_slots_file();
    for(i=1; i<argc; i++) {
        user = argv[i];
        printf("Searching user: %s\n", user);
        do_request_user_vcard(user);
    };

    save_vcards_tofile();

    if (1) {
        char vcard_buf[0x1000];

        save_vcards_tomem(vcard_buf, 0x1000);
        printf("%s\n", vcard_buf);
    };

    sockets_destroy();

    return 0;   
};

