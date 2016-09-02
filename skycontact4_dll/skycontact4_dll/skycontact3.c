// skycontact3.c : Skype protocol get contact list session reconstruction
//                                              (with normal crypto)
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


int main_skycontact(char *username, char *password) {
	char *ip;
	unsigned short port;
	int i;

	srand( time(NULL) );
	mip = mirsys(100, 0);

    //
    // TODO:
    // need add dns resolving for contact list server ips...
    //

	// login server
	//ip=strdup("91.190.218.40");
	//port=33033;

	// supernode connection
	//ip=strdup("157.55.235.147");
	//port=40030;

	// contact list server
	ip=strdup("91.190.216.125");
	port=12350;

	if (strlen(username) == 0) {
		printf("Please specify username.\n");
        return -1;
	};
	if (strlen(password) == 0) {
		printf("Please specify password.\n");
        return -1;
	};

	printf("Getting contact list for %s with password %s...\n", username, password);

	init_file();

	make_dh384_handshake(ip, port);

	i = do_skype_getcontacts(username, password);

	printf("Done!\n");

	return i;
}
