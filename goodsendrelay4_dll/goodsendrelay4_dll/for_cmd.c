//
// for run from cmd
//

#include <stdio.h>
#include <stdlib.h>

#include <string.h>
#include <time.h>
#include <windows.h>

#include <tchar.h>

extern int multysend_main(char* static_userip, char* static_msg);


int main(int argc, char* argv[]){
	int ret;

    if (argc < 2) { 
        debuglog("Usage error\n");
        return -1; 
    };

    if (strcmp(argv[1], "relay") == 0) {
        debuglog("\nDo relay connect.\n\n");
        ret = main_relay(argc, argv);
        return ret;
    };

    if (strcmp(argv[1], "direct") == 0) {
        debuglog("\nDo direct connect.\n\n");
        ret = main_direct(argc, argv);
        return ret;
    };

    debuglog_err("Mode unknown\n");

    return 0;
};


int main_direct(int argc, char* argv[]){
    int i;

    i = 1;


	//multysend_main("themagicforyou:192.168.1.75:57608", "test111");


    multysend_main(argv[2], argv[3]);

	//multysend_main(argv[2], "test111");


	//multysend_main("themagicforyou:192.168.1.135:14410", "test111");
    /*
	//multysend_main("themagicforyou:192.168.1.135:14410", "test1");
	//multysend_main("themagicforyou:192.168.1.135:14410", "This is skype msg1.");
	//multysend_main("themagicforyou:192.168.1.135:14410", "test1");
	//multysend_main("supamagic2:192.168.1.135:14410", "This is skype msg1.");
	//multysend_main("themagicforyou:192.168.1.135:14410", "test1");
    //multysend_main("xot_iam:192.168.1.170:5322", "test1");
	//multysend_main("supamagic2:192.168.1.135:14410", "This is skype msg1.");
	//multysend_main("supamagic2:192.168.1.135:14410", "test1");
	//multysend_main("themagicforyou:192.168.1.135:14410", "test3");
    //i = move_files(i);
    // move some files to another dir
    // mkdir
    // move
    //Sleep(75*1000);
    */

    /*    
	multysend_main("themagicforyou:192.168.1.135:14410", "test2");
    i = move_files(i);
	multysend_main("themagicforyou:192.168.1.135:14410", "test3");
    i = move_files(i);
	multysend_main("themagicforyou:192.168.1.135:14410", "test4");
    i = move_files(i);
	multysend_main("themagicforyou:192.168.1.135:14410", "test5");
    i = move_files(i);
	multysend_main("themagicforyou:192.168.1.135:14410", "test6");
    i = move_files(i);
	multysend_main("themagicforyou:192.168.1.135:14410", "test7");
    i = move_files(i);
	multysend_main("themagicforyou:192.168.1.135:14410", "test8");
    i = move_files(i);
	multysend_main("themagicforyou:192.168.1.135:14410", "test9");
    i = move_files(i);
	multysend_main("themagicforyou:192.168.1.135:14410", "test10");
    i = move_files(i);
    */

    return 0;
};


int main_relay(int argc, char* argv[]){
    int ret;
    size_t newsize;
    size_t newsize2;
    wchar_t *wcstring[0x1000];
    wchar_t *wcstring2[0x1000];
    char *orig;
    char *orig_myip;
	int i;

    orig_myip = argv[2];
    orig = argv[3];

    newsize = strlen(orig) + 1;
    newsize2 = strlen(orig_myip) + 1;

    if (argc < 1) {
        debuglog_err("Input error: not all parameters passed.\n");
        return -1;
    };

    debuglog("orig: %s\n", orig);
    debuglog("orig_myip: %s\n", orig_myip);

    convert_to_wchar(orig, newsize, wcstring);
    convert_to_wchar(orig_myip, newsize2, wcstring2);


    ret = relaysend_main(wcstring2, L"xot_iam", wcstring, L"test111_to_75_via_relay");

  	//ret = relaysend_main(wcstring2, L"themagicforyou", wcstring, L"test111_to_75_via_relay");


    //ret = relaysend_main("117.3.37.199","themagicforyou","0xdfeb5bd6897fdbf6-d-s157.55.235.160:40026-r117.3.37.199:14410-l192.168.1.135:14410", "Test msg1.");
    //ret = relaysend_main("117.3.37.199","themagicforyou","0xdfeb5bd6897fdbf6-d-s157.55.235.160:40026-r117.3.37.199:14410-l192.168.1.135:14410", "Msg2");
    //ret = relaysend_main("117.3.37.199","themagicforyou","0xdfeb5bd6897fdbf6-d-s157.55.235.160:40026-r117.3.37.199:14410-l192.168.1.135:14410", "Msg3");

    /*
    ret = relaysend_main("117.3.37.199","themagicforyou","0xdfeb5bd6897fdbf6-d-s157.55.235.160:40026-r117.3.37.199:14410-l192.168.1.135:14410", "Msg4");
    ret = relaysend_main("117.3.37.199","themagicforyou","0xdfeb5bd6897fdbf6-d-s157.55.235.160:40026-r117.3.37.199:14410-l192.168.1.135:14410", "Msg5");
    ret = relaysend_main("117.3.37.199","themagicforyou","0xdfeb5bd6897fdbf6-d-s157.55.235.160:40026-r117.3.37.199:14410-l192.168.1.135:14410", "Msg6");
    ret = relaysend_main("117.3.37.199","themagicforyou","0xdfeb5bd6897fdbf6-d-s157.55.235.160:40026-r117.3.37.199:14410-l192.168.1.135:14410", "Msg7");
    ret = relaysend_main("117.3.37.199","themagicforyou","0xdfeb5bd6897fdbf6-d-s157.55.235.160:40026-r117.3.37.199:14410-l192.168.1.135:14410", "Msg8");
    ret = relaysend_main("117.3.37.199","themagicforyou","0xdfeb5bd6897fdbf6-d-s157.55.235.160:40026-r117.3.37.199:14410-l192.168.1.135:14410", "Msg9");
    ret = relaysend_main("117.3.37.199","themagicforyou","0xdfeb5bd6897fdbf6-d-s157.55.235.160:40026-r117.3.37.199:14410-l192.168.1.135:14410", "Msg10");
    */

    //int relaysend_main(char* static_myip, char* static_username, char* static_uservcard, char* static_msg){
    //ret = relaysend_main(argv[2], argv[3], argv[4], "This is skype test msg.");

    return ret;
};



int move_files(int i) {
    char sdir[0x1000];

    memset(sdir, 0x00, 0x1000);

    sprintf(sdir, "log%d", i);
    mkdir(sdir);

    //rename("_good_chat_session.txt ", "log1\\_good_chat_session.txt ");
    //rename("_log.txt","log1\\_log.txt");
    //rename("_mylog.txt ","log1\\_mylog.txt .txt");
    //rename("_pktlog.txt","log1\\_pktlog.txt");
    //rename("_protolog.txt","log1\\_protolog.txt");

    // need copy, not remove!
    //sprintf(sdir, "log%d\\_good_chat_session.txt", i);
    //rename("_good_chat_session.txt", sdir);

    //sprintf(sdir, "log%d\\_log.txt", i);
    //rename("_log.txt", sdir);

    sprintf(sdir, "log%d\\_mylog.txt", i);
    rename("_mylog.txt", sdir);

    sprintf(sdir, "log%d\\_pktlog.txt", i);
    rename("_pktlog.txt", sdir);

    sprintf(sdir, "log%d\\_protolog.txt", i);
    rename("_protolog.txt", sdir);

    i++;

    return i;
};


int convert_to_wchar(char *orig, size_t newsize, wchar_t *wcstring) {
    size_t convertedChars;

    // Convert char* string to a wchar_t* string.
    convertedChars = 0;
    mbstowcs_s(&convertedChars, wcstring, newsize, orig, _TRUNCATE);

    return 1;

};
