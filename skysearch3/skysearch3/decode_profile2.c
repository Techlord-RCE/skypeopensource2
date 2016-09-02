//
// de-cipher signed profiles data
//

#include <stdio.h>

#include "short_types.h"


//
// forming nodeid vcard and ip:port pairs
//
int forming_vcard(u8 *skypename, u8 *ipinfo, u32 ipinfo_len) {
    u8 userid[0x100];
    u8 ipport_sup[0x100];
    u8 ipport_ext[0x100];
    u8 ipport_int[0x100];
    u32 port;
    u8 ipflag;
    char vcardstr[0x200];

    ipport_sup[0]=0;
    ipport_ext[0]=0;
    ipport_int[0]=0;
    userid[0]=0;

    if (1) {

        if (ipinfo_len==0) {
            printf("no ip block in profile!\n");
            return 0;
        };

        sprintf(userid,"0x%02x%02x%02x%02x%02x%02x%02x%02x",ipinfo[0],ipinfo[1],ipinfo[2],ipinfo[3],
                                            ipinfo[4],ipinfo[5],ipinfo[6],ipinfo[7]);

        // internal ip
        port=ipinfo[13]*0x100+ipinfo[14];
        sprintf(ipport_int,"%d.%d.%d.%d:%d",ipinfo[9],ipinfo[10],ipinfo[11],ipinfo[12],port);

        // supernode ip
        port=ipinfo[19]*0x100+ipinfo[20];
        sprintf(ipport_sup,"%d.%d.%d.%d:%d",ipinfo[15],ipinfo[16],ipinfo[17],ipinfo[18],port);

        // external ip
        port=ipinfo[25]*0x100+ipinfo[26];
        sprintf(ipport_ext,"%d.%d.%d.%d:%d",ipinfo[21],ipinfo[22],ipinfo[23],ipinfo[24],port);


        ipflag = ipinfo[8];
        printf("\nLearned new nodeinfo for %s: ipflag: 0x%x\n", skypename, ipflag);

        vcardstr[0]=0;

        // with username in vcard string
        /*
        if (ipflag) {
            // survive (alive) node
            //fprintf(fp,"%s - %s-s-s%s-r%s-l%s\n",skypename,userid,ipport_sup,ipport_ext,ipport_int);
            printf("%s - %s-s-s%s-r%s-l%s\n",skypename,userid,ipport_sup,ipport_ext,ipport_int);
            sprintf(vcardstr,"%s - %s-s-s%s-r%s-l%s\n",skypename,userid,ipport_sup,ipport_ext,ipport_int);
        } else {
            // dead node?
            // if flag == 0 replace int/ext ip addresses
            //fprintf(fp,"%s - %s-d-s%s-r%s-l%s\n",skypename,userid,ipport_sup,ipport_int,ipport_ext);
            printf("%s - %s-d-s%s-r%s-l%s\n",skypename,userid,ipport_sup,ipport_int,ipport_ext);
            sprintf(vcardstr,"%s - %s-d-s%s-r%s-l%s\n",skypename,userid,ipport_sup,ipport_int,ipport_ext);
        };
        */

        // without username in vcard string
        if (ipflag) {
            // survive (alive) node
            printf("%s-s-s%s-r%s-l%s\n",userid,ipport_sup,ipport_ext,ipport_int);
            sprintf(vcardstr,"%s-s-s%s-r%s-l%s\n",userid,ipport_sup,ipport_ext,ipport_int);
        } else {
            // dead node?
            // if flag == 0 replace int/ext ip addresses
            printf("%s-d-s%s-r%s-l%s\n",userid,ipport_sup,ipport_int,ipport_ext);
            sprintf(vcardstr,"%s-d-s%s-r%s-l%s\n",userid,ipport_sup,ipport_int,ipport_ext);
        };
        add_vcard(vcardstr);

        printf("\n");
    };

    return 0;
};


//
// process signed 0x188 block
//
int process_signed_block(u8 *membuf, u32 len) {
    int padding_len;
    u8 restdata[0x200];
    int restdata_len;
    u8 cred[0x188];
    u8 pubkey[0x80];
    u8 profile[0x1000];
    int profile_len;

    u8 ipinfo[0x100];
    u32 ipinfo_len=0;

    // dont change !
    // used in decode profile
    u8 skypename[1024];

    memset(skypename,0,sizeof(skypename));

    if (len-0x188 > 0x200) {
        printf("Some buffer error\n");
        return -1;
    };


    ipinfo_len = 0;
    profile_len = 0;

    memcpy(cred, membuf, 0x188);

    restdata_len = 0;
    if (len > 0x188) {
        restdata_len = len-0x188;
        memcpy(restdata, membuf+0x188, restdata_len);
    };
    
    skypename[0]=0;
    decode_profile(cred, pubkey, profile, skypename);
    
    if (restdata_len > 0) {
        memcpy(profile+0x80-0x15, restdata, restdata_len);
        show_memory_with_ascii(restdata, restdata_len, "extra data:");
        show_memory_with_ascii(profile, 0x80-0x15+restdata_len, "unsign data (with extra added):");
    };

    printf("\n::CREDENTIALS::\n");
    printf("Skypename: %s\n",skypename);

    printf("\nProfile:\n");

    if (profile[0] == 0x4B) {

        // skip padding
        padding_len = 0;
        while (profile[padding_len] != 0xBA){
            padding_len++;
            if (padding_len>=0x80){
                printf("Some strange unsigned data error (no last padding byte)\n");
                break;
            };
        };
        // some error, goto next
        if (padding_len == 0x80) {
            return -1;
        };
        // end of skip padding

        // should add rest bytes?

        // minus padding len in first
        // hash after padding len at first
        // and 0x15 hash after
        profile_len = 0x80-padding_len-0x15+restdata_len;

        main_unpack_profile(profile+padding_len+0x15, profile_len);
        main_unpack_get(profile+padding_len+0x15, profile_len, ipinfo, &ipinfo_len);
    };

    // data start right after 0x15 bytes
    if (profile[0] == 0x6A) {
        // remove hash before and hash after
        profile_len = 0x80-0x15-0x15+restdata_len;

        main_unpack_profile(profile+0x15, profile_len);
        main_unpack_get(profile+0x15, profile_len, ipinfo, &ipinfo_len);
    };

    if ((profile[0] != 0x6A) && (profile[0] != 0x4B)) {
        //some error
        printf("Unknown unsigned data error (no first padding byte)\n");
        return -1;
    };

    forming_vcard(skypename, ipinfo, ipinfo_len);

    return 0;
};


int get_profiles2(u8 *buf, u32 len) {
    u8 *ptr;
    int ret;
    u32 i;
    int p;
    u8 membuf[0x2000];
    int membuf_len;
    int pktnum;
    int next;

    printf("Len = 0x%x\n",len);

    pktnum = 0;
    next = 0;
    do {
        membuf_len = 0;
        ret = get_04_0B_blob_seq(buf, len, membuf, &membuf_len, pktnum, next);
        if ((ret < 0) || (membuf_len < 0)) {
            printf("Some buffer len error while getting 04-0B blob\n");
            return -1;
        };
        if (ret) {
            process_signed_block(membuf, membuf_len);
        };
        next++;
        if (next > 10) {
            printf("Some infinity loop error\n");
            return -1;
        };
    } while (ret==1);

    printf("\n:: END ::\n\n");

    return 0;
};

