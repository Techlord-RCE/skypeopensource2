
#define EXTERN_DLL_EXPORT __declspec(dllexport)

EXTERN_DLL_EXPORT int __stdcall skyauth(char *username, char *password) {
	int ret;

	printf("DLL Run OK.\n");

	printf("Starting Login process...\n");
	printf("Username: %s\n", username);
	printf("Password: %s\n", password);

	ret = main_skyauth4(username, password);

	printf("DLL Run Done.\n");

	return ret;
}
