// skyauth3.c: skype protocol login session reconstruction
//              with normal login packet construction
//              and random crypto data
//


#include <stdio.h>
#include <stdlib.h>

#include <string.h>  
#include <time.h>

#include <fcntl.h>
#include <io.h>

#include "miracl_lib/miracl.h"
#include "short_types.h"

#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")

miracl *mip;


char *gnu_basename(char *path) {
    char *base = strrchr(path, '\\');
    return base ? base+1 : path;
};


int main(int argc, char* argv[]) {
	char *ip;
	unsigned short port;
	unsigned short seqnum;
    int i;
	char *username;
	char *password;

	srand( time(NULL) );
	
	mip = mirsys (100, 0);
	
	ip=strdup("91.190.218.40");
	port=33033;
	
	//ip=strdup("157.55.235.147");
	//port=40030;

	//ip=strdup("192.168.1.17");
	//port=33864;

	if (argc != 3) {
		printf("Please specify username and password.\n");
		printf("Example: %s <someuser> <somepass>\n", gnu_basename(argv[0]));
		exit(1);
	};
	username = argv[1];
	password = argv[2];


	make_dh384_handshake(ip, port);

	i = do_skype_login(username, password);

    if (i==285){
        // successful login
        i = 1;
    } else {
        // login fail
        i = 0;
    };

	printf("Done!\n");

	return i;
}
