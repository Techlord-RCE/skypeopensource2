
#define EXTERN_DLL_EXPORT __declspec(dllexport)

EXTERN_DLL_EXPORT int __stdcall skycontact(char *username, char *password) {
	int ret;

	printf("DLL Run OK.\n");

	printf("Starting GetContacts process...\n");
	printf("Username: %s\n", username);
	printf("Password: %s\n", password);

	ret = main_skycontact(username, password);

	printf("DLL Run Done.\n");

	return ret;
}
