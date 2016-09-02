#include <stdio.h>
#include <stdlib.h>

#include <string.h>

#include <time.h>
#include <windows.h>


int main(int argc, char* argv[]){
	int ret;

    if (argc <= 2) { 
        debuglog("Usage error\n");
        return -1; 
    };

    if (strcmp(argv[1], "relay") == 0) {
        debuglog("\nDo relay connect.\n\n");
        ret = main_relay(argc, argv);
        return ret;
    };

    if (strcmp(argv[1], "direct") == 0) {
        debuglog("\nDo direct connect.\n\n");
        ret = main_direct(argc, argv);
        return ret;
    };

    debuglog("Mode unknown\n");

    return 0;
};

int main_direct(int argc, char* argv[]) {

	//skypechat_main("xot_iam:192.168.1.110:5322");

    skypechat_main(argv[2]);

    /*
    Sleep(30*1000);

    skypechat_main(argv[2]);

    Sleep(30*1000);

    skypechat_main(argv[2]);
    */

    return 0;
};


//
// relayrecv_main(static_myip, static_username, static_uservcard, msg);
//
int main_relay(int argc, char* argv[]) {
	int ret;
	char msg[0x1000];

	memset(msg, 0x00, 0x1000);

    ret = relayrecv_main("117.3.37.199","themagicforyou","0xdfeb5bd6897fdbf6-d-s157.55.235.160:40026-r117.3.37.199:14410-l192.168.1.135:14410", &msg);

    /*
    Sleep(30*1000);

	memset(msg, 0x00, 0x1000);
    ret = relayrecv_main("117.3.37.199","themagicforyou","0xdfeb5bd6897fdbf6-d-s157.55.235.160:40026-r117.3.37.199:14410-l192.168.1.135:14410", &msg);

    Sleep(30*1000);

	memset(msg, 0x00, 0x1000);
    ret = relayrecv_main("117.3.37.199","themagicforyou","0xdfeb5bd6897fdbf6-d-s157.55.235.160:40026-r117.3.37.199:14410-l192.168.1.135:14410", &msg);
    */

    //Sleep(30*1000);

	debuglog("MSG: %s\n", msg);

	return 0;
};

