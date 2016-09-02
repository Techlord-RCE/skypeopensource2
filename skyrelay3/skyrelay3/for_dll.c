
#define EXTERN_DLL_EXPORT __declspec(dllexport)

EXTERN_DLL_EXPORT int __stdcall skyrelay(char *myip, char *remote_name, char *vcard, char *output) {
	int ret;

	printf("DLL Run OK.\n");

	printf("Starting Skyrelay process...\n");

	printf("MYIP: %s\n", myip);
	printf("RemoteName: %s\n", remote_name);
	printf("VCARD: %s\n", vcard);
	
    //ret = skyrelay_main("95.52.232.99","notnowagainplease","0xe03e31ae403ae012-s-s65.55.223.25:40021-r95.52.236.102:57608-l192.168.1.75:57608", output);

	ret = skyrelay_main(myip, remote_name, vcard, output);

	printf("DLL Run Done.\n");

	return ret;
}

