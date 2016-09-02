#include <stdio.h>
#include <stdlib.h>

#include <fcntl.h>
#include <io.h>


#include "skype/skype_rc4.h"

// for aes
#include "crypto/rijndael.h"

// for 41 
#include "decode41.h"

extern char REMOTE_VERSION[0x100];
extern int REMOTE_VERSION_LEN;


int process_recv_data(char *recvbuf, int recvlen) {
    int tmplen;
    int blkseq;

    int checked_pkt_len;
    int i;

    int packet_type;
    int ret;

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
        u8 membuf[0x1000];
        int membuf_len;
        int ret;

        i++;

        printf("\n:: PROCESSING PKT %d ::\n", i);

        // show header
        show_memory(recvbuf+checked_pkt_len, 5, "Header");
        

        // pass 1-3 bytes of header
        header_len = 0;
        tmplen = get_packet_size2(recvbuf+checked_pkt_len, 4, &header_len);
        tmplen = tmplen-1;

        checked_pkt_len = checked_pkt_len+header_len;


        // pass marker byte
        printf("Marker byte: 0x%02X\n", recvbuf[checked_pkt_len]);
        if ( recvbuf[checked_pkt_len]!= 0x05 ){
            printf("Marker byte error, exiting..\n");
            exit(1);
        };
        checked_pkt_len++;

        // pass two bytes of AES pkt id
        printf("AES pkt id: 0x%02X%02X\n", recvbuf[checked_pkt_len], recvbuf[checked_pkt_len+1]);
        checked_pkt_len=checked_pkt_len+2;


        printf("pkt len: 0x%08X\n", tmplen);
        printf("checked_pkt_len: 0x%08X\n", checked_pkt_len);
        printf("fullpkt len: 0x%08X\n", recvlen);


        // aes len = -2 bytes from start, -2 bytes from end
        // -2 from end used as crc of whole pkt
        AES_DATA_len = tmplen-4;
        blkseq=get_blkseq(recvbuf+checked_pkt_len, AES_DATA_len+2);

        process_aes_crypt(recvbuf+checked_pkt_len, AES_DATA_len, 0, blkseq, 0);
        main_unpack(recvbuf+checked_pkt_len, AES_DATA_len);

        ret = get_03_2B_blob(recvbuf+checked_pkt_len, AES_DATA_len, REMOTE_VERSION);
        if (ret > 0) {
            REMOTE_VERSION_LEN = ret;
        };

        // pass 1-3 bytes of AES PKT DATA ID header (second AES data header?)
        header_len = 0;
        get_packet_size3(recvbuf+checked_pkt_len, 4, &header_len);
        
        packet_type = (int)recvbuf[checked_pkt_len+header_len] & 0xFF;
        printf ("PACKET TYPE: 0x%02X\n", packet_type);

        checked_pkt_len = checked_pkt_len + AES_DATA_len;

        // pass last two bytes of AES CRC
        printf("AES CRC: 0x%02X%02X\n", recvbuf[checked_pkt_len], recvbuf[checked_pkt_len+1]);
        checked_pkt_len=checked_pkt_len+2;


        printf("checked_pkt_len: 0x%08X\n", checked_pkt_len);
        printf("fullpkt len: 0x%08X\n", recvlen);

    };

    return 0;
};

