#include <stdio.h>
#include <stdlib.h>

#include <string.h>  
#include <time.h>

#include <fcntl.h>
#include <io.h>


char *gnu_basename(char *path) {
    char *base = strrchr(path, '\\');
    return base ? base+1 : path;
};


int main(int argc, char* argv[]) {
	char *username;
	char *password;

	if (argc != 3) {
		printf("Please specify username and password.\n");
		printf("Example: %s <someuser> <somepass>\n", gnu_basename(argv[0]));
		return -1;
	};
	username = argv[1];
	password = argv[2];

    main_skycontact(username, password);

	return 0;
}

