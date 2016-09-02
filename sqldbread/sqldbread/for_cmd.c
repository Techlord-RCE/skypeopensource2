//
// main.c code for sqllite3 testing
//
#include <stdio.h>
#include <stdlib.h>


// some standart defs
#ifndef uint
	#define uint           unsigned int
#endif
#ifndef u8
	#define u8             unsigned char
#endif
#ifndef u16
	#define u16            unsigned short
#endif
#ifndef u32
	#define u32            unsigned long
#endif
// end of defs


//
// just alternative copy of tcp_dbio.c for call functions
//

int main(){

    main_chats();

    return 0;
};


//
// proto for calling from goodsendrelay
//
int main_chats(){
    int ret;
    char CHAT_HISTORY[0x1000];
	char LOCAL_NAME[0x1000] = "notnowagainplease";
	char REMOTE_NAME[0x1000] = "themagicforyou";

    memset(CHAT_HISTORY, 0x00, sizeof(CHAT_HISTORY));
    
    // do load
    if (1) {

        ret = load_chathistory_from_db(LOCAL_NAME, REMOTE_NAME, CHAT_HISTORY);
		if (ret < 0) {
            return ret;
        };
        if (ret == 0) {
            // none found
            debuglog("No prev CHAT_HISTORY found for users: %s %s\n", LOCAL_NAME, REMOTE_NAME);
        };
        if (ret == 1) {
            // found something
            debuglog("CHAT_HISTORY found: %s\n", CHAT_HISTORY);
        };
    };

    return ret;
};

