//
// de-cipher signed profiles data
//

#include "short_types.h"


int get_profiles(u8 *buf, u32 len) {
	u8 *ptr;
	int ret;
	u32 i;
    int p;
	u8 cred[0x188];
	u8 pubkey[0x80];
	u8 profile[0x80];
	u8 ipinfo[0x100];
	u32 ipinfo_len=0;
    u8 ipflag;

	u8 userid[0x100];
	u8 ipport_int[0x100];
	u8 ipport_ext[0x100];
	u8 ipport_add[0x100];
	u32 port;


	// dont change !
	// used in decode profile
	u8 skypename[1024];

	memset(skypename,0,sizeof(skypename));

	printf("Len= 0x%x\n",len);

	for(i=0;(i+8)<len;i++){
		ptr=buf+i;
		ret=memcmp(ptr,"\x00\x00\x01\x04\x00\x00\x00\x01",8);
		if (ret==0){
			if (len-i>=0x188) {

				ipport_add[0]=0;
				ipport_ext[0]=0;
				ipport_int[0]=0;
				userid[0]=0;
				ipinfo_len=0;

				memcpy(cred,ptr,0x188);
				
				skypename[0]=0;
				decode_profile(cred, pubkey, profile, skypename);
				
				printf("\n::CREDENTIALS::\n");
				printf("Skypename: %s\n",skypename);

				printf("\nProfile:\n");

                if (profile[0] == 0x4B) {

                    p = 0;
                    while (profile[p] != 0xBA){
                        p++;
                        if (p>=0x80){
                            printf("Some strange unsigned data error (no last padding byte)\n");
                            break;
                        };
                    };
                    // some error, goto next
                    if (p == 0x80) {
             			i=i+0x187;
                        continue;
                    };
    				main_unpack_profile(profile+p+0x15, 0x80-p-0x15);
                    main_unpack_get(profile+p+0x15, 0x80-p-0x15, ipinfo, &ipinfo_len);
                };
                if (profile[0] == 0x6A) {
    				main_unpack_profile(profile+0x15, 0x80-0x15);
                    main_unpack_get(profile+0x15, 0x80-0x15, ipinfo, &ipinfo_len);
                };

                if ((profile[0] != 0x6A) && (profile[0] != 0x4B)) {
                    //some error
                    printf("Unknown unsigned data error (no first padding byte)\n");
					i=i+0x187;
                    continue;
                };

				//main_unpack_profile(profile+0x15, 0x80-0x15);
				//main_unpack_get(profile+0x15, 0x80-0x15, ipinfo, &ipinfo_len);

                //main_unpack_get(profile, 0x80, ipinfo, &ipinfo_len);
				//show_memory(ipinfo,ipinfo_len,"IP:");

				if (ipinfo_len==0) {
					printf("no ip block in profile!\n");
					i=i+0x187;
					continue;
				};

				sprintf(userid,"0x%x%x%x%x%x%x%x%x",ipinfo[0],ipinfo[1],ipinfo[2],ipinfo[3],
													ipinfo[4],ipinfo[5],ipinfo[6],ipinfo[7]);

				port=ipinfo[13]*0x100+ipinfo[14];
				sprintf(ipport_int,"%d.%d.%d.%d:%d",ipinfo[9],ipinfo[10],ipinfo[11],ipinfo[12],port);
				port=ipinfo[19]*0x100+ipinfo[20];
				sprintf(ipport_ext,"%d.%d.%d.%d:%d",ipinfo[15],ipinfo[16],ipinfo[17],ipinfo[18],port);

				if (ipinfo_len==27){
					port=ipinfo[25]*0x100+ipinfo[26];
					sprintf(ipport_add,"%d.%d.%d.%d:%d",ipinfo[21],ipinfo[22],ipinfo[23],ipinfo[24],port);
				}else{
					//ipport_add[0]=0;
					port=ipinfo[25]*0x100+ipinfo[26];
					sprintf(ipport_add,"%d.%d.%d.%d:%d",ipinfo[21],ipinfo[22],ipinfo[23],ipinfo[24],port);
				};

                ipflag = ipinfo[8];
   				printf("\nLearned new nodeinfo for %s: ipflag: 0x%x\n", skypename, ipflag);

                if (ipflag) {
                    // survive (alive) node
    	   			printf("%s-s-%s/%s %s\n",userid,ipport_ext,ipport_int,ipport_add);
                } else {
                    // dead node
    	   			printf("%s-d-%s/%s %s\n",userid,ipport_ext,ipport_int,ipport_add);
                };

                printf("\n");

				//memcpy(userid,ipinfo,8);
				//flag=ipinfo[9];
				//memcpy(&ipint,9,4);
				//memcpy(&portint,13,2);
				//memcpy(&ipext,15,4);
				//memcpy(&porext,19,2);

				i=i+0x187;
			};
		};
	};

	printf("\n:: END ::\n\n");

	return 0;
};

