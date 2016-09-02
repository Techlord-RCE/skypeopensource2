//
// for sql db io operations
//

#include <stdio.h>
#include <stdlib.h>

#include <string.h>
#include <windows.h>

#include "skype/skype_rc4.h"

#include "short_types.h"

extern u8 CHAT_STRING[0x100];
extern u8 REMOTE_NAME[0x100];
extern u8 LOCAL_NAME[0x100];
extern u8 MSG_TEXT[0x1000];

extern int insert_id[0x100];
extern int insert_id_len;


int load_lastsync_from_db(uint *cmd27_id, uint *cmd27_crc) {
    unsigned int local_header_id;
    unsigned int header_id_crc;
    unsigned int remote_header_id;

	debuglog("load_lastsync_from_db %s %s %s\n", CHAT_STRING, REMOTE_NAME, LOCAL_NAME);

    load_headers_from_db(CHAT_STRING, REMOTE_NAME, LOCAL_NAME, &local_header_id, &header_id_crc, &remote_header_id);

    *cmd27_id = remote_header_id;
    *cmd27_crc = header_id_crc;

    return 1;
};


int load_localheaders_from_db(uint *local_first, uint *tmp) {
    unsigned int local_header_id;
    unsigned int header_id_crc;
    unsigned int remote_header_id;

	debuglog("load_localheaders_from_db %s %s %s\n", CHAT_STRING, REMOTE_NAME, LOCAL_NAME);

    load_headers_from_db(CHAT_STRING, REMOTE_NAME, LOCAL_NAME, &local_header_id, &header_id_crc, &remote_header_id);

    *local_first = local_header_id;
    *tmp = header_id_crc;

    return 1;
};


int remove_messages_from_db() {
	int ret;
    int i;
    int row_id;

    ret = 0;

    for(i = 0; i < insert_id_len; i++){
        row_id = insert_id[i];
    	debuglog("On error, deleting row number: %d\n", row_id);
        ret = remove_from_db(row_id);
    };

	return ret;
};


int update_remoteheader_in_db(uint local_header_id, uint header_id_crc, uint remote_header_id) {
	int ret;

	debuglog("Updating remoteheader in db\n");
	debuglog("Updating CHAT_STRING: %s\n", CHAT_STRING);
    debuglog("Updating remote_header_id: 0x%08X\n", _bswap32(remote_header_id));
    debuglog("Updating local_header_id: 0x%08X\n", _bswap32(local_header_id));
    debuglog("Updating header_id_crc: 0x%08X\n", _bswap32(header_id_crc));

    // chat_string -- for select
    // local_header_id -- for select
    // header_id_crc -- for select
    // remote_header_id -- for update
    ret = update_rh_to_db(CHAT_STRING, local_header_id, header_id_crc, remote_header_id);

	return ret;
};


int save_message_to_db(uint local_header_id, uint header_id_crc, uint remote_header_id, char *msg,
    char *author, int is_service) {
	int ret;

	debuglog("Inserting message to db: %s %s %s\n", CHAT_STRING, REMOTE_NAME, LOCAL_NAME);

	debuglog("Message saved: %s\n", msg);

    ret = insert_to_db(CHAT_STRING, REMOTE_NAME, LOCAL_NAME,
                local_header_id, header_id_crc, remote_header_id, 
                msg, author, is_service);
    if (ret > 0) {
        insert_id[insert_id_len] = ret;
        insert_id_len++;
    } else {
        debuglog("Inserting in db error, do return...\n");
    };

	return ret;
};


int save_chatstring_to_db() {
	int ret;

	debuglog("Saving to db: %s %s %s\n", CHAT_STRING, REMOTE_NAME, LOCAL_NAME);

	ret = save_to_db(CHAT_STRING, REMOTE_NAME, LOCAL_NAME);

	return ret;
};


int load_chatstring_from_db(char *tmpbuf) {
	int ret;

	ret = load_from_db(tmpbuf, REMOTE_NAME, LOCAL_NAME);
	if (ret < 0) {
        debuglog("Some error occured during load_from_db. Users = %s %s\n", REMOTE_NAME, LOCAL_NAME);
	};
	if (ret == 0) {
		// none found
        debuglog("No prev CHAT_STRING found for users: %s %s\n", REMOTE_NAME, LOCAL_NAME);
	};
	if (ret == 1) {
		// found something
		debuglog("The prev CHAT_STRING found: %s\n", tmpbuf);
	};

	return ret;
};

