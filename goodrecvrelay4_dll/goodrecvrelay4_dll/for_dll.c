
#define EXTERN_DLL_EXPORT __declspec(dllexport)

EXTERN_DLL_EXPORT int __stdcall relayrecv(char *static_myip, char *static_username, char *static_uservcard, char *msg_unicode) {
	int ret;
    char msg_utf8[0x1000];

	debuglog("DLL Run OK.\n");

	debuglog("Starting RelaySend process...\n");

	debuglog("UserName: %s\n", static_username);
	debuglog("UserVCard: %s\n", static_uservcard);
	//debuglog("MSG: %s\n", static_msg);

    memset(msg_utf8, 0x00, sizeof(msg_utf8));
	
    //ret = relayrecv_main("117.1.1.1","notnowagainplease","0xe03e31ae403ae012-s-s65.55.223.25:40021-r95.52.236.102:57608-l192.168.1.75:57608", "This is skype msg, lol.");

	ret = relayrecv_main(static_myip, static_username, static_uservcard, msg_utf8);

	debuglog("MSG_UTF8: %s\n", msg_utf8);

    if (1) {
        // wcs string -- widechar aka unicode
        // REMOTE_MSG -- multybyte aka utf8

        Utf8ToUnicode(msg_unicode, msg_utf8, 0x1000);
        debuglog("msg_unicode: %s\n", msg_unicode);
    };

	debuglog("DLL Run Done.\n");

	return ret;
}


//
// just for future, not really needed now
//
EXTERN_DLL_EXPORT int __stdcall directrecv(char* static_username, char* static_ip, char* msg) {
	int ret;

	ret = skypechat_main("xot_iam:192.168.1.110:5322");

    return 0;
};

