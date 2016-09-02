// 

#include <stdlib.h>
#include <string.h>


#include "miracl_lib/miracl.h"
#include "short_types.h"

/*
int show_memory(char *mem, int len, char *text){
	int zz;
	int i;
	int k;
	char b[16+1];
	int t;

	debuglog("%s\n",text);
	debuglog("Len: 0x%08X\n",len);

	zz=0;
	k=0;
	b[16]=0;
	for(i=0;i<len;i++){
		debuglog("%02X ",mem[i] & 0xff);
		t=mem[i] & 0xff;
		if ((t>=0x20) && (t<=0x7f)){
			memcpy(b+k,mem+i,1);
		}else{
			memcpy(b+k,"\x20",1);
		};
		zz++;
		k++;
		if (zz == 16) { 
			zz=0;
			k=0;
            debuglog(" ; %s",b);
			debuglog("\n ");

		};
	};
	debuglog("\n");

	return 0;
};
*/

//
// parse argv2
//
int parse_input_line2(char *line, char *str_remote_skype, char *destip, char *destport) {
	int len;

	//debuglog("input line argv2: %s\n",line);

	// replace ":" to " "
	len=strlen(line);
	while(len){
		if (line[len]==':') line[len]=' ';
		len--;
	};

	sscanf(line,"%s %s %s",str_remote_skype,destip,destport);

	return 0;
};



//
// converting 2 bytes of ptr from ascii to hex
//
int convert_str_to_hex(char *ptr) {
		int hex_digit=0;

		if ((ptr[0]>=0x30) && (ptr[0]<=0x39)){
			hex_digit=ptr[0]-0x30;
		};
		if ((ptr[0]>='A') && (ptr[0]<='F')){
			hex_digit=ptr[0]-0x41+0x0A;
		};
		hex_digit=hex_digit<<4;

		//debuglog("ptr[i]=0x%08X\n",ptr[i]);
		//debuglog("hex_digit=0x%08X\n",hex_digit);


		if ((ptr[1]>=0x30) && (ptr[1]<=0x39)){
			hex_digit+=ptr[1]-0x30;
		};
		if ((ptr[1]>='A') && (ptr[1]<='F')){
			hex_digit+=ptr[1]-0x41+0x0A;
		};
		
		//debuglog("ptr[i]=0x%08X\n",ptr[i+1]);
		//debuglog("hex_digit=0x%08X\n",hex_digit);

		return hex_digit;
};

//
// Parse cred inputs argv1
//
int parse_input_line(char *line, u32 *secret_p, u32 *secret_q, char *str_skypename, char *user_cred) {
	u32					i;
	struct bigtype		p = {16, secret_p}, q = {16, secret_q};
	int len;
	u32 hex_digit;

	char str_password[0x1000];
	char str_firstlastnames[0x1000];
	char str_email[0x1000];
	char str_version[0x1000];
	char str_cred[0x1000];
	char str_p[0x1000];
	char str_q[0x1000];
	char *ptr;
	char *p_ptr;
	char *q_ptr;

	//debuglog("input line argv1: %s\n",line);

	// replace ":" to " "
	len=strlen(line);
	while(len){
		if (line[len]==':') line[len]=' ';
		len--;
	};

	sscanf(line,"%s %s %s %s %s %s %s %s",str_skypename,&str_password,&str_firstlastnames,&str_email,&str_version,
										  &str_cred,&str_p,&str_q);

	//debuglog("p=%s\n",str_p);
	//debuglog("q=%s\n",str_q);
	//debuglog("cred len=0x%08X\n",strlen(str_cred));

	ptr=strstr(str_cred,"00000001");
	if (ptr==NULL){
		debuglog("cred parsing error, no 00 00 00 01 sequence\n");
		return -1;
	};

	ptr=ptr+8;

	for(i=0;i<0x100;i++){
		hex_digit=convert_str_to_hex(ptr);
		//debuglog("hex_digit=0x%08X\n",hex_digit);		

		user_cred[i]=(char)hex_digit;

		ptr+=2;
	};
	
	//show_memory(user_cred,0x100,"cred bytes:");
	

	p_ptr=str_p;
	q_ptr=str_q;
	for (i = 0; i < 16; i++) {
		sscanf(p_ptr,"%x.", &p.w[i]);
		sscanf(q_ptr,"%x.", &q.w[i]);
		p_ptr+=9;
		q_ptr+=9;
	};


	p.w[15] |= 0x80000000, p.w[16] = 0;
	q.w[15] |= 0x80000000, q.w[16] = 0;

	//show_memory((char *)p.w,0x40,"p bytes:");
	//show_memory((char *)q.w,0x40,"q bytes:");

	
	return 0;
}



//
// restore pub/sec key
//
int restore_user_keypair (u32 *secret_p, u32 *secret_q, char *public_key_bytes, char *secret_key_bytes) {
	struct bigtype		p = {16, secret_p}, q = {16, secret_q};
	
	u32 public_key[33];
	u32 secret_key[33];
	struct bigtype		y = {32, (unsigned int *)&public_key};
	struct bigtype		z = {32, (unsigned int *)&secret_key};

	u32					_w[2] = {0x10001, 0};
	struct bigtype		w = {1, _w};


	p.w[16] = 0;
	q.w[16] = 0;
	multiply(&p, &q, &y);		// p*q = public key (not exactly, it's the common RSA modulus)
	decr (&p, 1, &p);			// p-1
	decr (&q, 1, &q);			// q-1
	multiply (&p, &q, &z);		// z = (p-1)*(q-1)
	incr (&p, 1, &p);			// p restored
	incr (&q, 1, &q);			// q restored
	xgcd (&w, &z, &z, &z, &z);	// z = 1/0x10001 mod (p-1)*(q-1), the secret exponent

	big_to_bytes(0x80,&y,public_key_bytes,TRUE);
	big_to_bytes(0x80,&z,secret_key_bytes,TRUE);

	show_memory(public_key_bytes,0x80,"public_key_bytes:");
	
	return 0;
}
