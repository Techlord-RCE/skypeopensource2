//
// tcp_recv.c -- receive data process module
//

#include "short_types.h"

extern int flag_auth_fail;
extern int flag_blob_04_35;
extern int flag_contacts_remain;
extern int flag_commands_remain;

extern char REMOTE_INDEXBUF[0x1000];
extern int REMOTE_INDEXBUF_LEN;


int init_file() {
    char *fp;

    fp = fopen("contacts.txt","w");
    fclose(fp);
};


int write_to_file(char *user) {
    char *fp;
    
    fp = fopen("contacts.txt","a");
    fprintf(fp, "%s\n", user);
    fclose(fp);

};




//
// main recv loop
//
int process_recv_data (char *recvbuf, int recvlen) {
	unsigned int tmplen;
	int blkseq;

	int checked_pkt_len;
	int i;

	int packet_type;

	//
	// PKT'S Processing
	//

	//printf("Process AES pkts in 57 41\n");
	
	printf("\nProcess AES pkts with 41\n");

	// init from prev processing
	checked_pkt_len=0;

	i=0;
	// main loop
	while(checked_pkt_len < recvlen){
		int header_len;
		int AES_DATA_len;
		unsigned char membuf[0x1000];
		int membuf_len;
		int ret;

		i++;

		printf("\n:: PROCESSING PKT %d ::\n", i);

		// show header
		show_memory(recvbuf+checked_pkt_len, 5, "Header");


		if (memcmp(recvbuf, "\x17\x03\x01", 3) != 0) {
			printf("SSL marker bytes error, return...\n");
			return -1;
		};
		checked_pkt_len+=3;

		// pass two bytes of AES pkt size
		printf("AES pkt size: 0x%02X%02X\n", recvbuf[checked_pkt_len], recvbuf[checked_pkt_len+1]);

		//
		// need get pkt size here...
		//


		//wrong
		//tmplen = recvlen - 7;

		// pass 2 bytes of header
		//memcpy((char *)&tmplen, recvbuf+checked_pkt_len, 2);

		// some fucking magic
		tmplen = ((unsigned char)recvbuf[checked_pkt_len] & 0xff)*0x100;
		tmplen += (unsigned char)recvbuf[checked_pkt_len+1] & 0xff;
		tmplen = tmplen-2;

		checked_pkt_len+=2;

		printf("tmplen (one processed pkt len): 0x%08X\n", tmplen);
		printf("checked_pkt_len: 0x%08X\n", checked_pkt_len);
		printf("fullpkt len: 0x%08X\n", recvlen);
		
		if (recvbuf[checked_pkt_len-2] == 0x01) {
			//return -1;
		};

        /*
        if ((checked_pkt_len + tmplen - 3) > recvlen) {
            printf("This is a last pkt\n");
            tmplen = recvlen - checked_pkt_len + 2;
            printf("New pkt len: %d (0x%08X)\n", tmplen, tmplen);
        };
        */


		// aes len = -2 bytes from start, -2 bytes from end
		// -2 from end used as crc of whole pkt
		AES_DATA_len = tmplen;
		blkseq=get_blkseq(recvbuf+checked_pkt_len, AES_DATA_len+2);

        process_aes_crypt2(recvbuf+checked_pkt_len, AES_DATA_len, 1, blkseq, 0);

		main_unpack_all(recvbuf+checked_pkt_len, AES_DATA_len);

        get_04_35_blob(recvbuf+checked_pkt_len, AES_DATA_len, REMOTE_INDEXBUF, &REMOTE_INDEXBUF_LEN);

        if (1) {
            int pkt_id = 0;
            get_00_02_blob(recvbuf+checked_pkt_len, AES_DATA_len, &pkt_id);
            if (pkt_id > 0) {
                printf("Got reply on pkt_id: 0x%02X\n", pkt_id);
            };
        };

        //00-01: D1 20 00 00
        if (1) {
            int pkt_id = 0;
            get_00_01_blob(recvbuf+checked_pkt_len, AES_DATA_len, &pkt_id);
            if (pkt_id > 0) {
                printf("Got reply on pkt_id: 0x%02X\n", pkt_id);
            };
        };

        if (1) {
            u8 remote_str[0x1000];
            int remote_str_len;
            get_04_33_blob(recvbuf+checked_pkt_len, AES_DATA_len,remote_str, &remote_str_len);
        };
		if (1) {
            u8 remote_str[0x1000];
            int remote_str_len;
            remote_str_len = get_03_34_blob(recvbuf+checked_pkt_len, AES_DATA_len, remote_str);
            if (remote_str_len > 0) {
                printf("Name: %s\n", remote_str);
                write_to_file(remote_str);
            };
		};



		/*
		// pass 1-3 bytes of AES PKT DATA ID header (second AES data header?)
		header_len = 0;
		get_packet_size3(recvbuf+checked_pkt_len, 4, &header_len);
		*/

		/*
		packet_type = (int)recvbuf[checked_pkt_len+header_len] & 0xFF;
		printf ("PACKET TYPE: 0x%02X\n", packet_type);
		*/

		checked_pkt_len = checked_pkt_len + AES_DATA_len;

		// pass last two bytes of AES CRC
		printf("AES CRC: 0x%02X%02X\n", recvbuf[checked_pkt_len], recvbuf[checked_pkt_len+1]);
		checked_pkt_len=checked_pkt_len+2;

		printf("checked_pkt_len: 0x%08X\n", checked_pkt_len);
		printf("fullpkt len: 0x%08X\n", recvlen);

	};

	return 0;
};

