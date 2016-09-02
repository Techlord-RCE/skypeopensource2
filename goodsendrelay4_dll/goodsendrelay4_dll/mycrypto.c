// crypto.c : Defines the entry point for the console application.
//

#include <stdio.h>


#include "crypto/sha1.h"

//extern void __fastcall SHA_hash (const void *data, unsigned long bytes, void *hash);

extern int rsa_sign(char *buf, int len, char *outbuf);
extern int rsa_unsign_cred(char *buf, int len, char *outbuf);
extern int rsa_decode(char *buf, int len, char *outbuf);
extern int rsa_encode(char *buf, int len, char *outbuf);

int _get_sha1_data(char *buf, int len, char *outbuf, int need_convert){
	unsigned int dwtmp;

	SHA1_hash(buf,len,outbuf);


	if (need_convert) {
		// invert data by integer big/little endian
		memcpy(&dwtmp,outbuf,4);
		dwtmp=_bswap32(dwtmp);
		memcpy(outbuf,&dwtmp,4);

		memcpy(&dwtmp,outbuf+4,4);
		dwtmp=_bswap32(dwtmp);
		memcpy(outbuf+4,&dwtmp,4);

		memcpy(&dwtmp,outbuf+8,4);
		dwtmp=_bswap32(dwtmp);
		memcpy(outbuf+8,&dwtmp,4);

		memcpy(&dwtmp,outbuf+12,4);
		dwtmp=_bswap32(dwtmp);
		memcpy(outbuf+12,&dwtmp,4);

		memcpy(&dwtmp,outbuf+16,4);
		dwtmp=_bswap32(dwtmp);
		memcpy(outbuf+16,&dwtmp,4);
	};



	return 0;
}



int _get_sign_data(char *buf, int len, char *outbuf){


	rsa_sign(buf,len,outbuf);




	return 0;
};

int _get_unsign_cred(char *buf, int len, char *outbuf){


	rsa_unsign_cred(buf,len,outbuf);


	return 0;
};

int _get_encode_data(char *buf, int len, char *outbuf){


	rsa_encode(buf,len,outbuf);


	return 0;

};

int _get_decode_data(char *buf, int len, char *outbuf){


	rsa_decode(buf,len,outbuf);


	return 0;

};


