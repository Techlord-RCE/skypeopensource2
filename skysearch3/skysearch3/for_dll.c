
#define EXTERN_DLL_EXPORT __declspec(dllexport)

EXTERN_DLL_EXPORT int __stdcall skysearch_getslots(int argc, char *argv[], char *myip) {
	int ret;
	int i;

	printf("DLL Run OK.\n");

	printf("Starting Search process...\n");
	printf("Arg Count: %d\n", argc);
	
	for (i=0; i<argc; i++) {
		printf("Arg V[%d]: %s\n", i, argv[i]);
	};
	//printf("Arg V[1]: %s\n", argv[1]);
	//printf("Arg V[2]: %s\n", argv[2]);

	ret = main_skysearch_getslots(argc, argv, myip);

	printf("DLL Run Done.\n");

	return ret;
}


// username - input
// vcard - output
EXTERN_DLL_EXPORT int __stdcall skysearch_one(char *username, char *vcard_buf, int maxlen) {
	int ret = 1;

	printf("DLL Run OK.\n");

	printf("Starting SearchOne Vcard process...\n");
	printf("For username: %s\n", username);

	ret = main_skysearch_one(username, vcard_buf, maxlen);

    //memset(vcard_buf, 0x41, maxlen);

	printf("Vcard: %s\n", vcard_buf);

	printf("DLL Run Done.\n");

	return ret;
}


// username - input
// vcard - output
EXTERN_DLL_EXPORT int __stdcall skysearch_many(int argc, char *argv[], char *vcard_buf, int maxlen) {
	int ret;
	int i;

	printf("DLL Run OK.\n");

	printf("Starting SearchMany Vcard process...\n");
	printf("Arg Count: %d\n", argc);
	for (i=0; i<argc; i++) {
		printf("Arg V[%d]: %s\n", i, argv[i]);
	};
	//printf("Arg V[0]: %s\n", argv[0]);
	//printf("Arg V[1]: %s\n", argv[1]);
	//printf("Arg V[2]: %s\n", argv[2]);

	ret = main_skysearch_many(argc, argv, vcard_buf, maxlen);

	printf("Vcard: %s\n", vcard_buf);

	printf("DLL Run Done.\n");

	return ret;
}

