
#define EXTERN_DLL_EXPORT __declspec(dllexport)

EXTERN_DLL_EXPORT int __stdcall load_chathistory(char *static_localname, char *static_remotename, char *chat_history_unicode) {
	int ret;
    char chat_history_utf8[0x1000];
	char localname[0x1000];
	char remotename[0x1000];

	debuglog("DLL Run OK.\n");

	debuglog("Starting load_chathistory_from_db process...\n");

    memset(chat_history_utf8, 0x00, sizeof(chat_history_utf8));
    memset(localname, 0x00, sizeof(localname));
    memset(remotename, 0x00, sizeof(remotename));

	UnicodeToAscii(localname, static_localname);
    UnicodeToAscii(remotename, static_remotename);

	debuglog("LOCAL_NAME: %s\n", localname);
	debuglog("REMOTE_NAME: %s\n", remotename);
	//debuglog("MSG: %s\n", static_msg);


    // do load
    if (1) {

        ret = load_chathistory_from_db(localname, remotename, chat_history_utf8);
		if (ret < 0) {
            return ret;
        };
        if (ret == 0) {
            // none found
            printf("No prev CHAT_HISTORY found for users: %s %s\n", localname, remotename);
        };
        if (ret == 1) {
            // found something
            printf("The prev CHAT_HISTORY found.\n");
        };
    };

	debuglog("MSG_UTF8: %s\n", chat_history_utf8);

    if (1) {
        // wcs string -- widechar aka unicode
        // REMOTE_MSG -- multybyte aka utf8

        Utf8ToUnicode(chat_history_unicode, chat_history_utf8, 0x1000);
        debuglog("msg_unicode: %s\n", chat_history_unicode);
    };

	debuglog("DLL Run Done.\n");

	return ret;
}

