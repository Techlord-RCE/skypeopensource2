// decrypt_41.cpp : Defines the entry point for the console application.
//


#include <stdio.h>
#include <stdlib.h>
#include <string.h>


//hexrays sdk
#include "defs.h"

#include "decode41.h"

int DEBUG=0;


int mysub_SessionManager_CMD_RECV_Process_00788E80(char *buf1, uint buflen1, char *selfptr);
int mysub_call_on_reply_check_possible_Flush_decode_pkt_header_decode_fail(uint, uint, uint, uint ,uint, char *selfptr);
int unpack_7_bit_encoded_to_dword(uint var1,uint var2,uint var3, char *selfptr);
int mysub_local_realloc_alloc_getlast_err_exception(unsigned int var1,unsigned int var2, char *selfptr);
int copy_memory1(unsigned int var1,unsigned int var2,unsigned int var3, char *selfptr);
int copy_memory2(unsigned int var1,unsigned int var2,unsigned int var3, char *selfptr);
int mysub_no_call_00724060(uint var1,uint var2,uint var3,uint var4,uint var5, char *selfptr);
int mysub_call_eax__free(uint var1,char *selfptr);
int mysub_unpack_7_bit_encoded(uint var1,uint var2,uint var3,uint var4,uint var5, char *selfptr);
int unpack_7_bit_encoded_to_dword___2(unsigned int var1,unsigned int var2,unsigned int var3, char *selfptr);
int mysub_local_alloc_memerr_exception(unsigned int var1, char *selfptr);
int print_buffer(char *str,unsigned int size, char *selfptr);
int print_buffer2(char *str,unsigned int size, char *selfptr);
int mygen_no_call_00927FF0(uint eax,uint ecx,uint edx,uint *eax11,uint *ecx11,uint *edx11, char *selfptr);

int mysub_some_vars_set_math_009278B0(int var1, unsigned __int8 var2, int var3, char *selfptr);
int mysub_local_alloc_memerr_exception_00714790(uint var1);


//
// Utils
//

//
// free-ing allocated buffers
//
int free_structure(char *selfptr){
	uint i;
	char *buf;

	
	struct self_s *self;
	self=(struct self_s *)selfptr;

	buf=self->heap_alloc_buf;
	free(buf);
	self->heap_alloc_buf_count=0;

	for(i=0;i<self->heap_alloc_struct_count;i++){
		buf=self->heap_alloc_struct_array[i];
		free(buf);
	};
	self->heap_alloc_struct_count=0;

	return 0;

};


//
// Print one buffer, detailed line by line
//
int print_structure_one_detail(char *str, char *selfptr, int index){
	unsigned int tmp,i,j,k;
	uint tmp1,tmp2,tmp3,tmp4,tmp5;
	char *buf;
	uint size;
	uint flag_k;

	struct self_s *self;
	self=(struct self_s *)selfptr;

	if (index==-1){
		buf=self->heap_alloc_buf;
		size=self->heap_alloc_buf_count;
	}else{
		buf=self->heap_alloc_struct_array[index];
		size=self->heap_alloc_struct_array_size[index];
	};

	if (index==-1){
		//printf("%s size(0x%08X)\n",str,size);
	}else{
		//printf("%s %d size(0x%08X)\n",str,index+1,size);
	};

	j=0;
	for(i=0;i<size;i=i+4){
		tmp=0;
		if (j==0){
			printf("next bytes: ");
		};
		if ((size-i)<4) {
			memcpy(&tmp,buf,size-i);
			if ((size-i)==3){
				printf("0x%06X ",tmp&0xffffff00);
			};
			if ((size-i)==2){
				printf("0x%04X ",tmp&0xffff0000);
			};
			if ((size-i)==1){
				printf("0x%02X ",tmp&0xff000000);
			};

		}else{
			memcpy(&tmp,buf,4);
			printf("0x%08X ",tmp);		
		};
		j++;
		if (j==1){
			tmp1=tmp;
		};
		if (j==2){
			tmp2=tmp;
		};
		if (j==3){
			tmp3=tmp;
		};
		if (j==4){
			tmp4=tmp;
		};
		if (j==5){
			tmp5=tmp;
		};
		if  ((j==5)||(i+4>=size)){ 
			j=0;
			printf("\n");
			printf("obj_type :  0x%08X\n",tmp1);
			printf("obj_index:  0x%08X\n",tmp2);
			printf("data:       0x%08X\n",tmp3);
			flag_k=-1;
			for (k=0;k<self->heap_alloc_struct_count;k++){
				if ( self->heap_alloc_struct_array[k] == (char *)tmp4 ){
					flag_k=k;
				};
			};
			if (flag_k==-1){
				printf("data_ptr:   0x%08X 0x%08X\n",tmp4,tmp5);
			}else{
				printf("data_ptr:   0xALLOC00%d 0x%08X\n",flag_k+1,tmp5);
			};
			printf("\n");
		};

		buf=buf+4;
	};

	printf("\n");

	return 0;
};



//
// Print one buffer
//
int print_structure_one(char *str, char *selfptr, int index){
	unsigned int tmp,i,j;
	char *buf;
	uint size;

	struct self_s *self;
	self=(struct self_s *)selfptr;

	if(index==-1){
		buf=self->heap_alloc_buf;
		size=self->heap_alloc_buf_count;
	}else{
		buf=self->heap_alloc_struct_array[index];
		size=self->heap_alloc_struct_array_size[index];
	};

	if (index==-1){
		printf("%s size(0x%08X)\n",str,size);
	}else{
		printf("%s %d size(0x%08X)\n",str,index+1,size);
	};

	j=0;
	for(i=0;i<size;i=i+4){
		tmp=0;
		if ((size-i)<4) {
			memcpy(&tmp,buf,size-i);
			if (index!=-1) tmp=bswap32(tmp);
			if ((size-i)==3){
				printf("%06X ",tmp&0xffffff00);
			};
			if ((size-i)==2){
				printf("%04X ",tmp&0xffff0000);
			};
			if ((size-i)==1){
				printf("%02X ",tmp&0xff000000);
			};

		}else{
			memcpy(&tmp,buf,4);
			if (index!=-1) tmp=bswap32(tmp);
			printf("%08X ",tmp);		
		};
		j++;
		if (j==4) { printf("| "); };
		if ((j==8)||(i+4>=size)) { 
			j=0; 
			printf("\n");
		};
		buf=buf+4;
	};

	printf("\n");

	return 0;
};


//
// Print logic
//
int print_structure(char *str, char *selfptr, int detail){
	uint i;

	
	struct self_s *self;
	self=(struct self_s *)selfptr;

	printf("==============================================\n");
	printf("%s\n",str);
	printf("==============================================\n");

	printf("Session id:  0x%08X (%d)\n",self->session_id, self->session_id);
	printf("Session cmd: 0x%08X (%d)\n",self->session_cmd, self->session_cmd);

	print_structure_one("MAIN:",selfptr,-1);

	if (detail) print_structure_one_detail("MAIN:",selfptr,-1);

	for(i=0;i<self->heap_alloc_struct_count;i++){

		print_structure_one("ALLOCATED:",selfptr,i);

	};


	return 0;
};


/*
*  Krasivo vivodim soderjimae heap_alloc_buf
*/

int print_buffer(char *str,unsigned int size1, char *selfptr){
	unsigned int tmp,i,j;
	char *buf;
	uint size;

	struct self_s *self;
	self=(struct self_s *)selfptr;

	buf=self->heap_alloc_buf;
	size=self->heap_alloc_buf_count;

	printf("MAINBUF %s size(0x%08X)\n",str,size);

	j=0;
	for(i=0;i<size;i=i+4){
		memcpy(&tmp,buf,4);
		printf("%08X ",tmp);		
		j++;
		if (j==4) { printf("| "); };
		if ((j==8)||(i+4>=size)) { 
			j=0; 
			printf("\n");
		};
		buf=buf+4;
	};


	return 0;
};

int print_buffer2(char *str,unsigned int size1, char *selfptr){
	unsigned int tmp,i,j;
	char *buf;
	uint size;

	struct self_s *self;
	self=(struct self_s *)selfptr;

	//current alloc
	buf=self->heap_alloc_struct_array[ (self->heap_alloc_struct_count-1) ];

	//size
	size=self->heap_alloc_struct_array_size[ (self->heap_alloc_struct_count-1) ];

	printf("%s size(0x%08X)\n",str,size);

	j=0;
	for(i=0;i<size;i=i+4){
		tmp=0;
		if ((size-i)<4) {
			memcpy(&tmp,buf,size-i);
			tmp=bswap32(tmp);
			if ((size-i)==3){
				printf("%06X ",tmp&0xffffff00);
			};
			if ((size-i)==2){
				printf("%04X ",tmp&0xffff0000);
			};
			if ((size-i)==1){
				printf("%02X ",tmp&0xff000000);
			};

		}else{
			memcpy(&tmp,buf,4);
			tmp=bswap32(tmp);
			printf("%08X ",tmp);		
		};
		j++;
		if (j==4) { printf("| "); };
		if ((j==8)||(i+4>=size)) { 
			j=0; 
			printf("\n");
		};
		buf=buf+4;
	};


	return 0;
};


//
// Main function 
// called from external
// unpack41
//
int unpack41_structure(char *buf, uint buflen, char *selfptr){
	int ret;
	struct self_s *self;
	self=(struct self_s *)selfptr;
	
	self->value_02c3f818=(unsigned int)buf;
	self->value_02c3f844=buflen;
	ret=mysub_SessionManager_CMD_RECV_Process_00788E80(buf,buflen,selfptr);
	
	if (ret==-2){
		return -2;
	};

	//last 2 bytes -- crc16
	if (self->value_02c3f844!=2) {

		//not all bytes decoded
		return -1;
	};


	return 0;
}




	//00789096:
	//proverka crc
	//vishe poschitali crc16 2 byte
	//sdes tolko sravnivaem
/*
mov     dl, [eax+esi-2]
mov     cl, [eax+esi-1]
shl     edx, 8
add     edx, ecx
mov     ecx, [ebp+var_20]
and     ecx, 0FFFFh
cmp     ecx, edx       
jnz     loc_7891E8      ; ne prigaem
proverka crc16
poslednie 2 byte - crc16
*/


/*
*    Schitaem pervie 3 byte of stream, session id
*    Poschitali session cmd, 6d=109 , obichno 1 byte
*    Call 0x41 decode function
*    Call handler procedure for 0x41 decoded pkt (mysub_session_manager_cmd_receive_big)
*
*/
int mysub_SessionManager_CMD_RECV_Process_00788E80(char *buf1, uint buflen1, char *selfptr){

			unsigned int eax,ebx,ecx,edx,edi,esi;
			uint ecx1;
			unsigned int ebp_4; //1
			unsigned int ebp_8;
			unsigned int ebp_10;//esi buf_ptr
			unsigned int ebp_14;//session_ptr?
			unsigned int ebp_18;
			unsigned int ebp_1c;//buf_cnt
			
			unsigned int ebp_24;//init with = 0
			unsigned int ebp_28;//..
			unsigned int ebp_2c;//..
			unsigned int ebp_30;//..00953898

			unsigned int ebp_34;
			char *buf_esi;
	
	struct self_s *self;
	self=(struct self_s *)selfptr;

	//self->value_02c3f818=1;
	//printf("2step=%d\n",self->value_02c3f818);
	//exit(-1);

	if (DEBUG) printf("ENTER mysub_SessionManager_CMD_RECV_Process_00788E80\n");




	//////////////////////////////////
	// initialization things
	//////////////////////////////////




	//esi=(unsigned int)buf;
	esi=self->value_02c3f818;

	//self->value_02c3f818=(unsigned int)buf;
	//self->value_02c3f844=buflen;

	self->value_02c3ed68=0;
	self->value_02e09da0=0x02e09da0;   // session cmd ptr..
	self->value_02c3f7f8=0;
    self->value_02c3f83c=0;

	//hz
	self->run_mysub_unpack_7_bit_encoded=0;

	//printf("%d\n",sizeof(char *));
	//exit(-1);

	// !!! maximum 100 ptrs... !!!
	//self->heap_alloc_struct_array=(char *)malloc(100 * sizeof(char *));
	self->heap_alloc_struct_array[0]=NULL;
	self->heap_alloc_struct_array_size[0]=0;
	self->heap_alloc_struct_count=0;

	
	//////////////////////////////////
	ebp_4=0;//??
	ebp_8=0x09;  // ???
	ebp_10=0;//store for curr buf ptr
	ebp_14=0; //CommandSessionManager::session_command_received(02E09DA0, 109, len=67)
	//ebp_14=0x02e09da0; //CommandSessionManager::session_command_received(02E09DA0, 109, len=67)
	ebp_18=0;  // nakoplenie predidushego byte
	ebp_1c=self->value_02c3f844;//buflen;
	ebp_34=0;//nakaplivaem predidushiy byte(for cycle 2)

	
	//eax=self->value_02c3f844;
	eax=ebp_1c;
			
	edi=0;

	// poschitaem session id
	// pervie 3 byte obichno


//cikl:
do {


	//cmp edi,20
	// ja jmp_vihod
	if (edi > 0x20) {
		printf("slishkom dohuya ciklov(>4) pri obrabotke int, jump on exit2, hz kuda\n");
		exit(-1);
	};



	//eax -- dlina pkt.
	//dec eax  
	eax--;
	//eax=0x48
	
	//mov ecx,edi //ecx=0
	ecx=edi;//7

	//mov [ebp+1c],eax  //=buf_cnt;
	self->value_02c3f844=eax;
	ebp_1c=eax;

	//mov dl,[esi] //esi=02c3f3e8 -- buf_pkt
	//--dl=d5 -- first byte

	//esi=self->value_02c3f818;
	buf_esi=(char *)esi;
	edx=buf_esi[0];

	//mov bl,dl
	ebx=edx;

	//inc esi
	esi++;

	//and ebx,7f
	ebx=ebx & 0x7f;

	//mov [ebp-10],esi	//ebp_10 curr buf ptr
	self->value_02c3f818=esi;
	ebp_10=esi;

	//shl ebx,cl
	ebx=ebx << ecx;

	//mov ecx,[ebp+18]
	ecx=ebp_18; //nakaplivaem predidushiy byte

	//add ecx,ebx //ecx=0//ebx=55
	ecx=ecx+ebx;

	//mov [ebp+18],ecx
	ebp_18=ecx;

	//printf("ecx=%X\n",ecx);

	//cmp dl, 80
	//dl=d5

	//if (edx < 0x80) {
	//	printf("jump on exit1\n");
	//	exit(-1);
	//};

	//add edi,7
	edi=edi+7;

	
	//test eax,eax


} while((eax != 0) && (edx >= 0x80));

	// poschitali session id
	// pervie 3 byte obichno
	if (DEBUG) printf("Session ID=%X \n",ecx);
	self->session_id=ecx;


	if (eax==0){
		printf("buflen==0, obrabotali ves pkt, na vihod, hz kuda\n");
		exit(-1);// hz
	};



	//xor edi,edi
	edi=0;

	//mov [ebp-34],edi
	ebp_34=edi;


	//poschitaem session cmd, 6d=109
	//obichno 1 byte


//cikl
do {
	//cmp edi,20
	// ja jmp_vihod
	if (edi > 0x20) {
		printf("slishkom doohuya(>4) ciklov, pri obrabotke int, jump on exit3\n");
		exit(-1);
	};



	//eax -- dlina pkt.
	//dec eax  
	eax--;
	//eax=0x45
	
	//mov ecx,edi //ecx=0
	ecx=edi;//0

	//mov [ebp+1c],eax  //=buf_cnt;
	self->value_02c3f844=eax;
	ebp_1c=eax;
	

	//mov dl,[esi] //esi=02c3f3eb -- buf_ptr
	//--dl=6d -- 4 byte

	//esi=self->value_02c3f818;
	buf_esi=(char *)esi;
	edx=buf_esi[0];

	//mov bl,dl
	ebx=edx;

	//inc esi
	esi++;

	//and ebx,7f
	ebx=ebx & 0x7f;

	//mov [ebp-10],esi	//ebp_10 curr buf ptr
	self->value_02c3f818=esi;
	ebp_10=esi;

	//shl ebx,cl
	ebx=ebx << ecx;
	//ebx=6d

	//mov ecx,ebx
	ecx=ebx;
	//ecx=6d

	//mov ebx,[ebp-34]
	ebx=ebp_34;
	//ebx=0

	//add ebx,ecx
	//ebx=6d
	ebx=ebx+ecx;

	//mov [ebp-34],ebx
	ebp_34=ebx; //nakaplivaem predidushiy byte2

	//printf("ebx=%X\n",ebx);

	//cmp dl, 80
	//dl=d5

	//add edi,7
	edi=edi+7;

	
	//test eax,eax

} while((eax != 0) && (edx >= 0x80));
	
	//poschitali session cmd, 6d=109
    if (DEBUG) printf("Session CMD=%X\n",ebx);
	self->session_cmd=ebx;


	if (eax==0){
		printf("buflen==0, obrabotali ves pkt, na vihod, hz kuda\n");
		exit(-1);// hz
	};


    //logika sess cmd and sess ptr

	//xor edi,edi
	edi=0;

	//cmp ebx,edi//ebx=6d//edi=0
	// if session cmd num = 0 ... oshibochka...
	if (ebx==edi) {
		printf("session cmd num = 0 , oshibochka, jump on hzkuda1\n");
		exit(-1);
	};

	//mov esi,[ebp+14]
	//esi=02e09da0

	self->value_02e09da0=0x02e09da0;

	//ebp_14=self->value_02e09da0;

	//kogda sessiya ustanovlenna znachenie = 02e09da0
	//inache 0
	esi=ebp_14;



	//xor edx,edx
	edx=0;

    //ebx, sess cmd num,  43..to esi(session cmd ptr)==0, ili oshibka
    //a esli ebx != 43, to esi(session cmd ptr)!=0, ili oshibka

	//cmp ebx,43
	//on x86, sete sets its operand to 1 if the zero/equal flag is set, and to 0 if it's not 
	//sete dl
	//dl=0
	if (ebx==0x43) { edx=1; } else { edx=0; };


	//xor eax,eax
	eax=0;

	//cmp esi,edi//esi=02e09da0//edi=0
	//sete al
	//al=0

	//printf("esi=0x%08X edi=0x%08X\n",esi,edi);

	if (esi==edi) { eax=1; } else { eax=0; };

	//printf("edx=0x%08X eax=0x%08X\n",edx,eax);


	//nujen flag, ukazivaushiy est sessiya ili net, eto hren
	//proveryaet established session ptr
	//cmp edx,eax //edx=0//eax=0
	if (edx!=eax) {
		//printf("session cmd 0x43, but sess cmd ptr not null, err, jump on hzkuda2\n");
		//exit(-1);
	};


	//cmp [ebp+8],edi//edi=0//ebp_8=0x09
	//ebp_8=0x09 chto eto.. hmm, odin iz parametrov dlya funkcii maybe..
	if (ebp_8==edi){
		printf("hmm, odin iz parametrov in this func call maybe,jump on hzkuda3\n");
		exit(-1);
	};


	//prepeare to call 0x41 decode function

	//edi=0

	//mov [ebp-24],edi
	//mov [ebp-28],edi
	//mov [ebp-2c],edi
	//mov [ebp-30],0x00953898

	ebp_24=edi;//=0
	ebp_28=edi;
	ebp_2c=edi;
	ebp_30=0x00953898; //some, may be static addr, for 02c3f7f8
	//po adressu 0x00953898; -- 02c3f7f8 
	//self->value_02c3f7f8=0;


	//lea eax,[ebp+14]
	eax=ebp_14; //buf_ptr//eax=02c3f83c
    //hmm ohh.. data from session ptr... hm or just ebp+14...
    //po adressu session ptr -- 02c3f83c
    //self->value_02c3f83c=0;
	eax=self->value_02c3f83c;

	//lea ecx,[ebp+1c]
	ecx=ebp_1c; //buf_cnt//ecx=02c3f844
	ecx=self->value_02c3f844;

	
	//push eax//02c3f83c
	//push 8
	//push edi//=0
	
	//lea edx,[ebp-10]//edx=02c3f818 ptr on buf..
	edx=ebp_10;
	edx=self->value_02c3f818;

	//push ecx//02c3f844
	ecx1=ecx;

	//push edx//02c3f818

	//lea ecx,[ebp-30]//ecx=02c3f7f8
	ecx=ebp_30;
    self->value_02c3f7f8=0;


	//mov [ebp-4],1
	ebp_4=1;

	//mov [ebp+14],0x04b000
	ebp_14=0x04b000;
	self->value_02c3f83c=ebp_14;

	// call
	//push eax//02c3f83c     //new alloc buf max len = 0x04b000
	//push 8
	//push edi//=0
	//push ecx1//02c3f844
	//push edx//02c3f818
	//printf("edx=%X,ecx1=%X,0=%X,8=%X,eax=%X\n",edx,ecx1,0,8,eax);
	eax=mysub_call_on_reply_check_possible_Flush_decode_pkt_header_decode_fail(edx,ecx1,0,8,eax,selfptr);

	//sanity checks

	//test al,al
	//if al!=0 jmp 007891c2
	//prigaem
	if (eax==0) {
		printf("Flush_decode.. call fail with ret=0, jump on hzkuda4\n");
		//exit(-1);
		return -2;
	};


	//cmp [ebp+1c],2
	//if [ebp+1c] < 2 jmp ..
	//ne prigaem
	//self->value_02c3f844 < 2 //
	if (ebp_1c < 2) {
		printf("rest of len <2, no CRC at end of stream, jump on hzkuda5\n");
		exit(-1);
	};

	//edi=0
	//esi=02e09da0 //session ptr
	//cmp esi,edi
	//if esi!=edi jmp
	//prigaem
	
	//if (esi==edi){
	if (esi!=edi){
		//printf("session ptr nil, after decode call, i think is not good :), jump on hzkuda6\n");
		//exit(-1);
	};
	
	//prepare to call handler procedure for decoded pkt

	//EBP=02C3F828
	//mov ecx,[ebp+8] 
	//ecx=9
	ecx=ebp_8;

	//mov edx,[ebp+18] //edx=86d5 //session id
	edx=ebp_18;

	//lea eax,[ebp-30] //eax=02c3f7f8
	eax=ebp_30;
	eax=self->value_02c3f7f8;

	//push eax //eax=02c3f7f8 //some struct.. with pointer on decoded buffer..
	//push ecx //09 // hz...???
	//push edx //0x86d5 //session id
	//push ebx //6d //cmd id

	//mov ecx,esi////ecx=02e09da0
	ecx=esi;
	ecx=self->value_02e09da0;


	esi=self->value_02c3f818;
	buf_esi=(char *)esi;
	//edx=buf_esi[1];

	if (DEBUG) printf("last bytes ( 0x%02X 0x%02X 0x%02X 0x%02X )\n",buf_esi[0]&0xff,buf_esi[1]&0xff,buf_esi[2]&0xff,buf_esi[3]&0xff);

	if (DEBUG) printf("left=0x%08X buflen=0x%08X\n",self->value_02c3f844, buflen1, selfptr);

	if (DEBUG) print_buffer("COMPLETED:",0x40, selfptr);

	if (DEBUG) print_buffer2("LAST_STR_STRUCT:",0x20, selfptr);

	//call unexplored 
	//TODO: ?
	//0078920D: CALL Skype14.0086B140
	//mysub_session_manager_cmd_receive_big();


	//unexplored here also

	if (DEBUG) printf("LEAVE mysub_SessionManager_CMD_RECV_Process_00788E80\n");

	return 0;
};









/*
*  Checking encoding marker(0x41)
*  Processing first int from stream, and save it in global var
*     Cikl, postepennoe videlenie pamyati, sohr v 02c3f7fc, na pervom shage i na 20-om..
*        zanulenie buffer-a 02c3ed70 razmerom 16 byte
*        skopiruem 0x14 byte(00 00..) iz 02c3ed70 v heap_alloc_buf..
*        check on memory corrupt, by calling mysub_call_eax__free
*        vizov mysub_unpack_7_bit_encoded
*     Ciklov stoka je skoka perviy dekodirovanniy int
*  Vihod
*/


// call
//push eax//02c3f83c	//var5//new alloc buf max len = 0x04b000
//push 8				//var4
//push edi//=0			//var3
//push ecx1//02c3f844 //var2  len
//push edx //02c3f818 //var1  curr_buf_ptr
int mysub_call_on_reply_check_possible_Flush_decode_pkt_header_decode_fail(uint var1,uint var2,uint var3,uint var4,uint var5,
																	   char *selfptr){

			unsigned int eax,ebx,ecx,edx,edi,esi,ebp;
			char *buf_ebp;
			unsigned int esp_14,esp_10,esp_18,esp_1c,esp_55c,esp_56c,esp_570,esp_578;
			unsigned int esi_4,esi_8,ecx1;

			
	struct self_s *self;
	self=(struct self_s *)selfptr;

	if (DEBUG) printf("ENTER: mysub_call_on_reply_check_possible_Flush_decode_pkt_header_decode_fail\n");


	//for tests only
	self->value_02c3f818=var1;
	self->value_02c3f844=var2;

	//mov eax, [esp+56c] -- 02c3f818
	//mov ebp, [eax] -- 02c3f3ec (buf + 5) on 41..

	//eax=self->value_02c3f818;

	ebp=self->value_02c3f818;//buf_ptr;

	edx=self->value_02c3f844;//bytes left, buflen;

	memset(self->value_02c3ed70_ptr,0,0x14);
	//self->value_02c3ed70=0; //hz poka

	//printf("ebp=%X,edx=%X\n",ebp,edx);

	//first byte of encoding analyse
	//must be 0x41

	buf_ebp=(char *)ebp;
	//cmp [ebp],41

	if (buf_ebp[0]!=0x41){
		printf("NOT 41 ENCODING !!! Maybe 42 ?\n");
		printf("jump on hzkuda6\n");
		exit(-1);
	};

//00723e13:

	//dec edx --edx 45
	//edx=44
	edx--;

	//next byte to process

	//push ecx -- 02c3f844 -- &counter //var2//edx?

	//mov [ecx],edx -- 44 
	//ecx=edx; //?
	self->value_02c3f844=edx;

	//mov edx,[eax]  --edx= ptr on buff 02c3f3ec , eax=02c3f818 ptr on ptr on buff
	//edx=var1;
	edx=self->value_02c3f818;

	//inc edx   -- edx ukazivaet na perviy byte posle 41
	edx++;

	//push eax -- 02c3f818

	//mov [eax],edx   sohranyaem buf ptr
	self->value_02c3f818=edx;

	//lea eax,[esp+1c]
	//--eax=02c3ed68
	self->value_02c3ed68=0;
	eax=self->value_02c3ed68;


	//raspakovivaem pervie byte after 0x41 encoder marker
	//sohranyaem v 02c3ed68

	//push eax//02c3ed68

	//call
	//push ecx -- 02c3f844//counter
	//push eax -- 02c3f818//ptronbuf
	//push eax//02c3ed68//sohranenniy schitanniy perviy byte 
	//call unpack_7_bit_encoded_to_dword();
	eax=unpack_7_bit_encoded_to_dword(self->value_02c3ed68,self->value_02c3f818,self->value_02c3f844,selfptr);
	
    //printf("first decoded int, self->value_02c3ed68=%X\n",self->value_02c3ed68);
	if (DEBUG) printf("First INT:%X\n",self->value_02c3ed68);

	//test al,al
	if (eax==0){
		printf("first int decode error,hz kuda 7\n");
		exit(-1);
	};

//00723e35:


	//kolvo ciklov vsego

	//esp_14=4;
	esp_14=self->value_02c3ed68;
	//mov eax,[esp+14] --eax=4
	eax=esp_14;


	//kolvo ciklov uje kounter
	//mov [esp+10],0
	esp_10=0;

	//proerka pervogo int

	//test eax,eax
	//if eax<=0 jmp ..
	if (eax<=0){
		printf("first int <=0, guess is a error.., hz kuda 8\n");
		//exit(-1);
		return 0;
	};

	//mov ebx, [esp+57c]
	//--ebx=02c3f83c
	//ebx=var5;
	ebx=self->value_02c3f83c;//max buf len 0x04b000

	//printf("ebx=%X\n",ebx);

	esi_8=0;  //cikl inrement var
	esi_4=0;  //kolo ciklo do malloc-a(0,0x20,0x40..)

	self->value_02c3f7fc=0;//sdes budet ptr on alloc buf

	esp_18=self->value_02c3f7f8;
	esi=esp_18;

	//{kogda jmp to cikl
//jmp 00723e52:
	//mov esi, [esp+18] //esi=02c3f7f8
	//esp_18=0x02c3f7f8;
	
	

do {

	//esi=self->value_02c3f7f8;
	//shag 2
	//}
//jmp 00723e56:


	//mov eax,[ebx] --ebx=02c3f83c 
	//--eax=0004b000
	//--eax=0004afec
	//--eax=0004afd8
	//eax=0004af93
    //eax=self->value_02c3f83c;

	ebx=self->value_02c3f83c;
	eax=ebx;
	//eax=ebx;

	//if size of left bytes, 0x14=20

	//cmp eax, 14
	//if eax=14 jmp ..
	//ne prigaem
	if (eax==0x14) {
		printf("esli tochno 0x14 bytes ostalos v novom buffere, to buffer konchilsya..jmp hz kuda 9");
		exit(-1);
	};


	//add eax,-14
	//--eax =0x0004afec
	//--eax =0x0004afd8
	//--eax =0x0004afc4
	//--eax =0x0004af7f
	eax=eax-0x14;//-0x14 ot ostatka buffera
	
	//printf("eax=0x%08X\n",eax);

	//self->value_02c3f83c=eax;

	//output buf
	self->heap_alloc_buf_count=self->heap_alloc_buf_count+0x14;

	//add esi,4 --esi = 02c3f7f8
	//--esi=02c3f7fc
	//--esi=02c3f7fc
	//--esi=02c3f7fc
	//esi=esi+4; //hmm
	//tolko ptr vostanavlivaetsya..

	esi=self->value_02c3f7fc;//esi ne menyaetsya v konce cikla, ono menyaetsya cherez counteri

	//mov [ebx],eax  //save some counter
	//ebx=eax;
	self->value_02c3f83c=eax;

	//mov ebp,[esi+8]
	//--ebp=0 
	//ebp=1
	//ebp=2
	//ebp=3
	
	ebp=esi_8;


	//mov eax,[esi+4] 
	//--eax=0
	//eax=20
	//eax=20
	//eax=20
	eax=esi_4;

	//zahodim esli kol-vo ciklov >=0x20...
	//ili perviy cikl
	//zahodim kajdiy 0x20 cikl.. t.e. vizivaem malloc i uvelichivaem kol-vo pamyati 4 raza min..

	//cmp ebp,eax
	//if ebp < eax  jmp ..
	//{shag 2 : prigaem.. propuskaem alloc
	//jmp   00723e8c
	//};
	if (ebp >= eax){
		//lea ecx, [ebp+ebp*4+a0]  --ebp=0
		//--ecx=a0
		ecx=ebp+ebp*4+0xa0;// 0xa0==160
		
		//shl ecx,2
		//--ecx=0280
		ecx=ecx << 2;

		//push ecx  --size

		//--esi=02c3f7fc
		//push esi  -- ptr//self->value_02c3f7fc

		esi=self->value_02c3f7fc;

		//call 00714800
		//push ecx  --size
		//push esi  -- ptr//self->value_02c3f7fc
		mysub_local_realloc_alloc_getlast_err_exception(esi,ecx,selfptr);
		//02c3f7fc -- saved ptr on allocated buffer
      
		esi=self->value_02c3f7fc;

		//mov eax,[esi+4] --esi = 02c3f7fc
		//--eax=0
		eax=esi_4;
		
		//add esp,8

		//add eax,20 
		//--eax=20
		eax=eax+0x20;


		//mov [esi+4],eax --eax=20
		esi_4=eax;
	};

	
//00723e8c:




	//mov ecx, [esi+8] 
	//--ecx=0
	//--ecx=1--esi=02c3f7fc
	//ecx=2
	//ecx=3
	ecx=esi_8;//cikl kounter


	//mov eax,[esi]
	//--eax =02e32ee8 -- ptr on alloc buf 280h size ..
	//--esi=02c3f7fc
	//eax=02e32ee8
	eax=esi;
	//eax=self->value_02c3f7fc;


	//lea edi, [ebp+ebp*4] --ebp =0
	//--edi=0
	//ebp=1
	//edi=5
	//edi=0a
	//edi=0f
	edi=ebp+ebp*4;  //some counter..

	//lea edx, [ecx+ecx*4] --ecx=0
	//--edx=0
	//ecx=1
	//edx=5
	//ecx=2
	//edx=0a
	//edx=0f
	edx=ecx+ecx*4;//also..

	//shl edi,2
	//--edi=0
	//edi=14
	//edi=28
	//edi=3c
	edi=edi << 2;

	//shl edx,2
	//--edx=0
	//edx=14
	//edx=28
	//edx=3c
	edx=edx << 2;

	//sub edx,edi
	//--edx=0
	//edx=0
	edx=edx-edi;   //nakuya neponyatno


	//lea ecx,[eax+edi] --eax=alloc buf, edi=0
	//--ecx=alloc buf =02e32ee8
	//eax=alloc
	//edi=14
	//ecx=alloc+14
	//edi=28
	//ecx=alloc+28
	//edi=3c
	//ecx=alloc+3c=02e32f24
	ecx=eax+edi;     //ptr+0,0x14,...

	//push edx --0  //0
	//0


	//lea edx,[ebp+ebp*4+5]  -- ebp=0
	//--edx=5
	//ebp=1
	//edx=a
	//ebp=2
	//edx=0f
	//ebp=3
	//edx=14
	edx=ebp+ebp*4+5;

	//push ecx --ecx= alloc buf+...
	//ecx=alloc+14
	//ecx=alloc+28
	//ecx=alloc+3c
	

	//lea eax, [eax+edx*4] --eax alloc buf, --edx=5 
	//--eax=alloc_buf+0x14 = 02e32efc
	//eax=alloc //edx=0a //eax=alloc+28
	//eax=alloc //edx=0f //eax=alloc+3c
	//eax=alloc //edx=14 //eax=alloc+50=02e32f38
	eax=eax+edx*4;

	//push eax  -alloc buf +0x14
	//alloc buf +0x28
	//eax=alloc+3c
	//eax=alloc+50

	//call 00927000
	//( copy_memory(allocbuf+14,allocbuf,0) )
	//( copy_memory(allocbuf+28,allocbuf+14,0) )
	//eax=02e32f10
	//esi=02c3f7fc
	//edi=14
	//ebp=1
	//( copy_memory(allocbuf+3c,allocbuf+28,0) )
	//( copy_memory(allocbuf+50,allocbuf+3c,0) )

	//printf("eax=%X,ecx=%X, diff=%X, heap_alloc_buf=%X\n",eax,ecx,eax-ecx,self->value_02c3f7fc);
	copy_memory1(eax,ecx,0,selfptr);
	//che delaet neponyatno poka..skoree vsego nichego


	//mov edx, [esi+8] //esi=02c3f7fc
	//edx=0
	//edx=1
	//edx=2
	//edx=3
	edx=esi_8; // counter


	//add esp,0c
	
	//inc edx //edx=1
	//edx=2
	//edx=3
	//edx=4
	edx++;

	//lea ecx,[esp+1c] //02c3ed70
	//ecx=02c3ed70
	esp_1c=(uint ) self->value_02c3ed70_ptr;
	ecx=esp_1c;
    //dalshe sravnivaetsya pri kopi memory2 heap_alloc_buf

	//push 0
	//push 0
	//push 0
	//push 0

	//mov [esi+8],edx 
	esi_8=edx;  //cikl counter++ 

	//zabili 00-lyamu 02c3ed70 

	//printf("ed70:0x%08X\n",self->value_02c3ed70_ptr);
	//printf("ed7_:0x%08X\n",ecx);

	//mysub_no_call_00724060
	mysub_no_call_00724060(0,0,0,0,ecx,selfptr);

	//mov edx, [esi] //edx=02e32ee8 =alloc buf
	//esi=self->value_02c3f7fc;
	edx=esi;

	//lea ecx,[esp+1c] //ecx=02c3ed70
	//ecx=self->value_02c3f7fc;
	ecx=esp_1c;

	//push 14

	//add edx,edi  //edx=alloc buf, edi=0
	//edx=alloc buf
	//edi=14 //edx=allocbuf+14
	//edi=28 //edx=allocbuf+28 = 02e32f10
	//edi=3c //edx=allocbuf+3c = 02e32f24
	edx=edx+edi;

	//push ecx // 02c3ed70

	//push edx //alloc buf
	//alloc buf+14
	//alloc buf+28
	//alloc buf+3c



	//skopiruem 0x14 byte(00 00..) iz 02c3ed70 v heap_alloc_buf..

	//call copy_memory
	//copy_memory(alloc_buf,02c3ed70(nuls),0x14);
	//copy_memory(alloc_buf+14,02c3ed70(nuls),0x14);
	//copy_memory(alloc_buf+28,02c3ed70(nuls),0x14);
	//copy_memory(alloc_buf+3c,02c3ed70(nuls),0x14);
	//{zabili nulyami alloc buf +..}
	//push 14
	//push ecx // 02c3ed70
	//push edx //alloc buf
	//printf("edx=%X,ecx=%X\n",edx,ecx);
	//edx,self->value_02c3ed70,0x14
	//copy_memory2(edx,ecx,0x14);
	copy_memory2(edx,ecx,0x14,selfptr);


	//esi=02c3f7fc
	//mov esi,[esi] 
	//esi=02e32ee8

	//esi=self->value_02c3f7fc;

	//add esp,0c

	//ecx=5
	//lea ecx,[esp+1c]
	//ecx=02c3ed70
	ecx=esp_1c;
	//ecx=self->value_02c3ed70;

	//esi=alloc
	//edi=0
	//add esi,edi
	//esi=alloc
	//esi=alloc+14
	//esi=alloc+28
	//esi=alloc+3c=02e32f24
	//edi=0,0x14,..
	esi=esi+edi;


	//check on memory corrupt

	//call 007242f0
	//(mysub_call_eax__free)
	//(mysub_call_eax__free)
	mysub_call_eax__free(ecx,selfptr);


	//mov eax,[esp+578] //eax=8
	esp_578=var4;//8;
	eax=esp_578;
	eax=var4;

	//mov ecx,[esp+570] //ecx=02c3f844
	esp_570=var2;
	ecx=esp_570;
	ecx=self->value_02c3f844;

	//mov edx,[esp+56c] //edx=02c3f818
	esp_56c=var1;
	edx=esp_56c;
	edx=self->value_02c3f818;


	//push ebx // 02c3f83c
	//push eax // 08
	//push ecx // 02c3f844
	//push edx // 02c3f818


	//mov ecx,esi //esi=alloc=02e32ee8
	//ecx=alloc
	//ecx=alloc+14
	//ecx=alloc+28
	//ecx=alloc+3c=02e32f24

	ecx1=esi;

	//call 007246a0 
	//(mysub_unpack_7_bit_encoded)
	//push ecx1 //ecx=alloc, alloc+0x14..//self->value_02c3f7fc.
	//push ebx // 02c3f83c//self->value_02c3f83c//max len buff
	//push eax // 08
	//push ecx // 02c3f844
	//push edx // 02c3f818
	eax=mysub_unpack_7_bit_encoded(edx,ecx,eax,ebx,ecx1,selfptr);
	edx=self->value_02c3f818;
	ecx=self->value_02c3f844;


	//test al,al 

	//if al == 0 jmp 
	//ne prigaem..
	if (eax==0) {
			printf("error code 0 returned after mysub_unpack_7_bit_encoded, hz 21\n");
			exit(-1);
	};

	//mov eax , [esp+10 ] //eax=0
	//eax=1
	//eax=2
	//eax=3
	eax=esp_10;  //ciklov vsego curr counter ..

	//mov ecx,[esp+14] //ecx=04
	//ecx=4
	//ecx=4
	//ecx=4
	ecx=esp_14;   // kolvo ciklov voobshe iz self->value_02c3ed68, gde lejit perviy dekodirovanniy int

	//inc eax //eax=01
	//eax=2
	//eax=3
	//eax=4
	eax++;

	//cmp eax,ecx 

	//mov [esp+10],eax //save cikl counter
	esp_10=eax;

	//if eax < ecx jmp v cikl ..
	//jb jmp
	//prigaem
}
while (eax < ecx);

    //ciklov stoka je skoka perviy dekodirovanniy int

	//mov al,1
	eax=1;

	//mov ecx,[esp+55c] //ecx=02c3f81c
	esp_55c=0x02c3f81c;
	ecx=esp_55c;
	//neponyatno poka chto eto


	//pop edi //edi=0
	//pop esi //esi=02e09da0
	//pop ebp //ebp=02c3f828
	//pop ebx //ebx=6d

	//mov fs:[0],ecx
	//add esp,558
	//retn 14

	if (DEBUG) printf("LEAVE: mysub_call_on_reply_check_possible_Flush_decode_pkt_header_decode_fail\n");

	return eax;
};







/*
*  Sobstvenno decodirovanie
*  vizivaet funkciu kotoraya dekodit neskolko byte iz paketa v 1 integer.
*   
*  6-oy byte pkt_data kopiruem v 4byte new alloc buffera, -- poluchaem 1 int 
*  t.e. perviy posle kol-va ciklov byte, kopiruem srazu v 1-iy integer heap_alloc_buf,
*  4-iy integer zapolnyaem 0-lem
*  vizivaem unpack_7_bit_encoded_to_dword___2 dlya decodinga 2 integera v heap_alloc_buf
*  nachinaem so sleduushego byte 41 04(chislo ciklov) , 00(perviy skopirovanniy int v heap_alloc_buf), 
*  sleduuchiy 01(decoditsya toje v 01 eto integer 2) ..
*  dalee proveryaetsya chto perviy integer == 0 ili net. esli raven, dekodim sleduushiy integer uje 3 
*  t.e. vizivaem funkciu unpack_7_bit_encoded_to_dword___2 opyat, ona prodoljaet dekodit, eto uje bytes 8D B5 D0 CA 03,
*  dekodit integer do poyavlenie byte < 0x80.. vse zapisali 3 integer, vihodim iz funkcii.
*  1 cikl iz 4-h done.
*
*  A teper ponyatnee, suda peredaetsya ptr na alloc buf +0,+0x14...
*  v nego zapolnyautsya 4 ili 5 integera, poluchautsya oni tak:
*  1 int eto tupo sled byte iz pkt_buf
*  4 int = 0 
*  2 int eto sled byte do byte <=0x80, raspakovivaetsya cherez unpack_7_bit_encoded_to_dword___2
*  dalee smotritsya esli 1 int != 0 zahodim v if ...
*  esli 1 int = 0 to dekodim dalshe 3 byte.
*  i vihodim
*
*  esli zahodim v if, to proveryaem, chemu raven 1 int..
*  poka issledovan toka sluchay kogda int == 4 (string?) i int==1(?? key? seed?)
*  schitivaem/dekodim byte 0x31 - dlina, sohranyem v int 5
*  delaem sanity check na razmer dlini, max buffer len - razmer buffera, 
*  videlaem buffer
*  sohranyaem pointer na buffer videlenniy v int 4,
*  copiruem tuda 0x31 byte dlini
*  vichitam dlinu iz countera v i pribavlaem k kolichestvu proydennih byte v pkt_buf
*  vihodim, t.e. esli 4 byte !=0 t.e. ptr na strukturu a v 5 ee razmer.
*  1 int - tip obekta(tip strukturi integer, string etc.. ?)
*  2 int - chislo kakoeto(nomer poryadkoviy obj?, index ?)
*  3 int - chislo ili 0 , esli 0 to sledom idet ptr i size(ili 2 byte hz, dannih,dlya 1 int==1)
*  4 int - 0 ili pointer na obj(string)
*  5 int - 0 ili dlina
*/


//push ecx1 //ecx=alloc, alloc+0x14...
//push ebx // 02c3f83c//max len buffer 0x04b000
//push eax // 08
//push ecx // 02c3f844//counter
//push edx // 02c3f818//buffer
int mysub_unpack_7_bit_encoded(uint var1,uint var2,uint var3,uint var4,uint var5, char *selfptr){

		unsigned int ebx,eax,ecx,esi,ebp,edi,edx;
		unsigned int esp_c,esp_14/*,esp_20*/;
		unsigned char *edx_buf;

		uint eax11;
		uint ecx11;
		uint edx11;

		int ebp1;

	struct self_s *self;
	self=(struct self_s *)selfptr;

	if (DEBUG) printf("ENTER mysub_unpack_7_bit_encoded\n");

	self->run_mysub_unpack_7_bit_encoded++;
	//push ebx

	
	if (DEBUG) printf("heap_alloc_buf=%X,var5=%X\n",self->heap_alloc_buf,var5);

	if (self->run_mysub_unpack_7_bit_encoded==2){
		//exit(-1);
	};

	//mov ebx, [esp+c] //ebx=02c3f844  sohranenniy counter
	esp_c=var2;
	ebx=esp_c;
	ebx=self->value_02c3f844;

	//push ebx
	//push esi

	//mov eax,[ebx] //eax=43 counter
	//eax=3c
	//eax=39
	//eax=5
	eax=ebx;

	ecx=var5;
	//ecx=self->value_02c3f7fc;//alloc
	//mov esi,ecx //var5
	esi=ecx;

	//xor ebp,ebp
	//ebp=0
	ebp=0;
	
	//push edi  //0?
	//3c ???
	
	//lea ecx,[eax-1] //ecx=42
	//ecx=3b
	//ecx=38
	//ecx=4
	ecx=eax-1;

	//mov [ebx],ecx // sohranyaem counter
	ebx=ecx;
	self->value_02c3f844=ecx;

	//cmp eax,ebp //ebp=0
	//if eax=0 jmp ..
	//je ..
	//ne pprigaem
	if (eax==0){
		printf("buffer konchilsya ranshe vremeni buflen=0, hz 22\n");
		exit(-1);
	};


	//mov edi,[esp+14]  //edi=02c3f818 --ptr on buf
	esp_14=var1;
	edi=esp_14;
	edi=self->value_02c3f818;


	//xor eax,eax
	eax=0;

	//push ebx //ebx=02c3f844  sohranenniy counter

	//lea ecx,[esi+4] //ecx=02e32eec alloc_buf+4
	//ecx=02e32f00 alloc_buf+18
	//ecx=02e32f14 alloc_buf+14+14+4 =alloc_buf+2c
	//ecx=02e32f28 alloc_buf+14+14+14+4=alloc_buf+40
	ecx=esi+4;   // 2 int
	//ecx=self->value_02c3f7fc+4;

	//mov edx,[edi] //edx=02c3f3ee
	//02c3f3e8 + 6,  buf_pkt+6
	//02c3f3f5  buf_pkt + 13 13 byte buffera
	//02c3f3f8  buf_pkt + 15 15 byte buffera
	//02c3f42c buf_pkt+ 44
	edx=edi;
	edx=self->value_02c3f818;

	//push edi //edi=02c3f818 --ptr on buf

	//push ecx //ecx=02e32eec alloc_buf+4
	//ecx=02e32f00 alloc_buf+18
	//ecx=02e32f14 alloc_buf+14+14+4 =alloc_buf+2c
	//ecx=02e32f28  =alloc+40

	//mov al,[edx] //al = 00 , 6-y byte buffera
	//mem breakpoint on read 
	//al=0, 13 byte buffera
	//al=4, 15(16) byte buffera
	//al=0 44 byte buffera	
	edx_buf=(unsigned char *)self->value_02c3f818;	
	eax=edx_buf[0];
	if (DEBUG) printf("1:READ BYTE7b=%X\n",eax);

	//6-oy byte pkt_data kopiruem v 4byte new alloc buffera, 1 int 

	//mov [esi],eax   //esi=02c3f844 //eax=0
	//save znachenie v alloc buf
	//heap_alloc_buf=(char *)self->value_02c3f7fc;
    //memcpy(heap_alloc_buf,&eax,4);
	
    memcpy((char *)esi,&eax,4); //1 int = byte from buffer
	//printf("eax=%X\n",eax);

	//mov eax,[edi] //eax=02c3f3ee buf+6
	//eax= 02c3f3f5  buf_pkt + 13
	//eax= 02c3f3f8  buf_pkt + 16
	//eax=02c3f42c buf+44
	eax=self->value_02c3f818;

	//inc eax
	//buf+7
	//02c3f3ef
	//02c3f3f6  buf_pkt + 14
	//02c3f3f9  buf_pkt + 17
	//eax=02c3f42d buf+45
	eax++;

	//mov [edi],eax //edi=02c3f818 , eax ptr on buf
	edi=eax;
	self->value_02c3f818=eax;

	//new alloc buf+0xc , kopiruem 0.. 4 int 

	//mov [esi+c],ebp //ebp=0 //esi=02c3f7fc
	//ebp=0 //esi=alloc+14
	//ebp=0//esi=02E32F10 alloc+28
	//ebp=0
	//esi_c=ebp;
	//heap_alloc_buf=(char *)self->value_02c3f7fc;
    //memcpy(heap_alloc_buf+0xc,&ebp,4);
	memcpy((char *)esi+0xc,&ebp,4);//4 int = 0

	//call 00723220
	//push ebx //ebx=02c3f844 --sohranenniy counter
	//push edi //edi=02c3f818 --ptr on buf
	//push ecx //ecx=02e32eec --alloc_buf+4//self->value_02c3f7fc+4  // 2 int !
	//ecx=02e32f00 alloc_buf+18
	//ecx=02e32f10 alloc_buf+28
	//ecx=02e32f28 alloc_buf+40
	//unpack_7_bit_encoded_to_dword___2(ecx,edi,ebx)
	eax=unpack_7_bit_encoded_to_dword___2(ecx,edi,ebx,selfptr);

	edi=self->value_02c3f818;
	ebx=self->value_02c3f844;

	// sdes uje est pervie 3 int heap_alloc_buf 00 00 00 00   00 00 00 01  00 00 00 00

	//add esp,0c

	//test al,al
	//if al=0 jmp ..
	//ne prigaem

	if (eax==0){
		printf("unpack_7_bit_encoded_to_dword___2 returned with error , hz 24\n");
		exit(-1);
	};

	//mov eax, [esi]  //esi=alloc=02e32ee8//self->value_02c3f7fc
	//eax=0
	//alloc+14 = 02e32efc 
	//eax=esi;
	//esi_buf=(unsigned char *)self->value_02c3f7fc;
	//memcpy(&eax,esi_buf,4);
	memcpy(&eax,(char *)esi,4); //dobivaem znachenie pervogo int

	if (DEBUG) print_buffer("2:",0x20,selfptr);

	//printf("heap_alloc_buf=%X,self->value_02c3f7fc=%X\n",heap_alloc_buf,self->value_02c3f7fc);
	//exit(-1);
	if (DEBUG) printf("IF: eax=%X,ebp=%X\n",eax,ebp);
	//exit(-1);

	//cmp eax,ebp  //eax=0//ebp=0
	//eax=4//ebp=0
	//if eax!=ebp jmp 00724702 prigaem kogda eax=4 {
	//{
	//00724702:

	//zahodim esli znachenie pervogo int != 0

	if (eax !=ebp){
		
		//exit(-1);

		//cmp eax,1
		//jnz 0072474F
		//prigaem:
		//0072474F:
		if (eax == 1){
			if (DEBUG) printf("perviy int = 1\n");

			//loc_724702:

			//printf("ebx=0x%08X buflen=0x%08X\n",ebx/*self->value_02c3f844*/,buflen);
			
			//esli ostavshayasya dlina < 8, to prigaem na vihod, al=0

			//CMP DWORD PTR DS:[EBX],8
			//JB SHORT Skype14.007246F9
			if (ebx < 8) {
				//007246F9:
				//pop     edi
				//pop     esi
				//pop     ebp

				//xor     al, al
				eax=0;

				//pop     ebx
				//retn    10h
				return eax;
			};

			//printf("esi=0x%08X\n",esi);
			//printf("ebp=0x%08X\n",ebp);

			//MOV DWORD PTR DS:[ESI+C],EBP
			//MOV DWORD PTR DS:[ESI+10],EBP

			memcpy((char *)esi+0xc,&ebp,4);
			memcpy((char *)esi+0x10,&ebp,4);

			//print_buffer("2.1:",0x20);

			//MOV EBP,38
			ebp=0x38;
			ebp1=ebp;

			//loc_724717:

		   do {
			//MOV EDX,DWORD PTR DS:[EDI]
			//edx=self->value_02c3f818
			edx=edi;

			//XOR EAX,EAX
			eax=0;

			//MOV ECX,EBP
			ecx=ebp1;

			//MOV AL,BYTE PTR DS:[EDX]
			edx_buf=(unsigned char *)edx;//self->value_02c3f818;
			eax=edx_buf[0];

			//printf("eax=0x%08X\n",eax);


			//	Convert double-word to quad-word
			//Sign-extends EAX into EDX, forming the quad-word EDX:EAX. 
			//Since (I)DIV uses EDX:EAX as its input, 
			//CDQ must be called after setting EAX 
			//if EDX is not manually initialized (as in 64/32 division) before (I)DIV.
			//edx=0;
			//CDQ
			//edx=eax;

			eax11=eax;
			edx11=edx;
			__asm {
				mov eax,eax11;
				mov edx,edx11;
				cdq
				mov eax11,eax;
				mov edx11,edx;
			};
			eax=eax11;
			edx=edx11;

			//printf("ecx=0x%08X\n",ecx);
			//printf("edx=0x%08X\n",edx);

			//CALL Skype14.00927FF0
			mygen_no_call_00927FF0(eax,ecx,edx,&eax11,&ecx11,&edx11,selfptr);

			eax=eax11;
			ecx=ecx11;
			edx=edx11;

			//printf("aft eax=0x%08X\n",eax);
			//printf("aft ecx=0x%08X\n",ecx);
			//printf("aft edx=0x%08X\n",edx);

			//MOV ECX,DWORD PTR DS:[ESI+C]
			memcpy(&ecx,(char *)esi+0xc,4); 

			//OR ECX,EAX
			ecx=ecx | eax;

			//MOV DWORD PTR DS:[ESI+C],ECX
			memcpy((char *)esi+0xc,&ecx,4);

			//MOV EAX,DWORD PTR DS:[ESI+10]
			memcpy(&eax,(char *)esi+0x10,4); 

			//OR EAX,EDX
			eax=eax | edx;

			//MOV DWORD PTR DS:[ESI+10],EAX
			memcpy((char *)esi+0x10,&eax,4);

			//poryadok dvuh integer pomenyalsya.
			
			//printf("ecx=0x%08X\n",ecx);
			//printf("eax=0x%08X\n",eax);


			//MOV ECX,DWORD PTR DS:[EDI]
			//edi=self->value_02c3f818;
			ecx=edi;

			//INC ECX
			ecx++;

			//SUB EBP,8
			ebp1=ebp1-8;

			//MOV DWORD PTR DS:[EDI],ECX
			edi=ecx;
			self->value_02c3f818=ecx;


			//printf("ebp1=0x%08X\n",ebp1);

			//JNS SHORT Skype14.00724717
		   }while(ebp1>=0);
		
			//exit(-1);

			//not really needed
			ebp=ebp1;

			//print_buffer("2.3:",0x20);

			//self->value_02c3f844
			//MOV EAX,DWORD PTR DS:[EBX]
			//eax=self->value_02c3f844;
			eax=ebx;

			//POP EDI

			//ADD EAX,-8
			eax=eax-8;

			//POP ESI

			//self->value_02c3f844
			//MOV DWORD PTR DS:[EBX],EAX
			self->value_02c3f844=eax;
			ebx=eax;


			//POP EBP
			//MOV AL,1
			eax=1;

			//POP EBX
			//RETN 10

			//exit(-1);
			return eax;
		};

		//cmp eax,2
		//jnz 007247A0
		//prigaem
		//007247A0:
		if (eax == 2){
			printf("perviy int = 2, hz 27\n");
			exit(-1);
		};

		//cmp eax,3
		//jnz 0072480F
		//prigaem
		//0072480F:
		if (eax == 3){

			//printf("perviy int = 3, hz 28\n");

			//MOV EDX,DWORD PTR DS:[EBX]
			//ebx=self->value_02c3f844;
			edx=ebx;

			//printf("edx=0x%08X\n",edx);

			//MOV EAX,DWORD PTR DS:[EDI]
			//edi=self->value_02c3f818;
			eax=edi;

			//printf("eax=0x%08X\n",eax);

			//printf("ebp=0x%08X\n",ebp);
			
			//print_buffer("3_3.1:",0x20,selfptr);


			//PUSH EDX//value_02c3f844, len
			//PUSH EBP//=0
			//PUSH EAX//value_02c3f818 buf ptr
			//CALL Skype14.009278B0

			//mysub_some_vars_set_math_009278B0(self->value_02c3f818,ebp,self->value_02c3f844);
			eax=mysub_some_vars_set_math_009278B0(self->value_02c3f818,0,self->value_02c3f844,selfptr);

			//eax -- ptr gde obekt zakanchivaetsya

			//printf("buf_ptr= 0x%08X eax=0x%08X\n",self->value_02c3f818,eax);
			//print_buffer("3_3.2:",0x20,selfptr);

			//CMP EAX,EBP
			//JE Skype14.007246F9
			// if eax == 0 ...
			if (eax==ebp){
				printf("size 0, when processing first int = 3\n");
				exit(-1);
			};

			//MOV ECX,DWORD PTR DS:[EDI]
			//edi=self->value_02c3f818;
			ecx=edi;
			// ecx -- ptr na current buf

			//esp_20=var4;

			//MOV EDX,DWORD PTR SS:[ESP+20]
			edx=self->value_02c3f83c; //max len

			//SUB EAX,ECX
			eax=eax-ecx;
			//eax -- size, for this object

			//printf("eax=0x%08X\n",eax);

			//LEA ECX,DWORD PTR DS:[EAX+1]
			ecx=eax+1;

			//MOV DWORD PTR DS:[ESI+10],ECX
			//ecx=self->value_02c3f7fc;//alloc , allocated bug
			//esi+0x10 -- 5 integer --
			memcpy((char *)esi+0x10,&ecx,4);

			//MOV EAX,DWORD PTR DS:[EDX]
			eax=edx;
			
			//printf("eax=0x%08X\n",eax);

			//CMP EAX,ECX
			//JB Skype14.007246F9

			//eax ostalos buffera
			//ecx skoka nado buffera + 1
			if (eax<ecx) {
				printf("buffer menshe chem nada dlya obekta, first int = 3\n");
				exit(-1);
			};

			//SUB EAX,ECX
			eax=eax-ecx;

			//printf("eax=0x%08X\n",eax);

			//MOV DWORD PTR DS:[EDX],EAX
			edx=eax;
			self->value_02c3f83c=edx;

			//MOV ECX,DWORD PTR DS:[ESI+10]
			// dostaem 5 integer, eto razmer
			memcpy(&ecx,(char *)esi+0x10,4);			

			//razmer dannih, razmer buffera kotoriy nujno malloc
			//PUSH ECX
			//CALL Skype14.00714790
			//mysub_local_alloc_memerr_exception_00714790(ecx);
			
			//funkciya dlya malloc-a
			eax=mysub_local_alloc_memerr_exception(ecx,selfptr);

			//MOV EDX,DWORD PTR DS:[ESI+10]
			// dostaem 5 integer
			memcpy(&edx,(char *)esi+0x10,4);

			//MOV DWORD PTR DS:[ESI+C],EAX
			// save ptr on malloc buf, in -- 4 integer --
			memcpy((char *)esi+0x0c,&eax,4);


			//MOV ECX,DWORD PTR DS:[EDI]
			//edi=self->value_02c3f818;
			//curr buf ptr
			ecx=edi;

			
			//PUSH EDX// size of object to copy
			//PUSH ECX//src, otkuda kopi
			//PUSH EAX//dst,kuda kopi
			//CALL Skype14.00927000
			copy_memory2(eax,ecx,edx,selfptr);

			//print_buffer2("3.3_3:",0x20,selfptr);


			//MOV EDX,DWORD PTR DS:[ESI+10]
			// dostaem 5 integer
			memcpy(&edx,(char *)esi+0x10,4);

			//MOV EBP,DWORD PTR DS:[EDI]
			//curr buf ptr
			ebp=edi;

			//ADD EBP,EDX
			//curr buf ptr + object size
			ebp=ebp+edx;

			//ADD ESP,10

			//MOV DWORD PTR DS:[EDI],EBP
			//edi=self->value_02c3f818;
			edi=ebp;
			self->value_02c3f818=edi;

			//MOV EAX,DWORD PTR DS:[ESI+10]
			// dostaem 5 integer
			memcpy(&eax,(char *)esi+0x10,4);

			//MOV ECX,DWORD PTR DS:[EBX]
			//ebx=self->value_02c3f844;
			//ostalos byte v buffere
			ecx=ebx;
			
			//POP EDI
			//SUB ECX,EAX
			//iz ostalos byte v buffere
			//vichitaem, 5 integer, razmer objekta schitannogo
			ecx=ecx-eax;

			//POP ESI			
			//MOV DWORD PTR DS:[EBX],ECX
			//ebx=self->value_02c3f844;
			//sohranyaem
			ebx=ecx;
			self->value_02c3f844=ebx;

			//POP EBP
			//MOV AL,1
			eax=1;

			//POP EBX
			//RETN 10
			return eax;
		};

		//cmp eax,4
		//jnz 00724880
		//ne prigaem
		if (eax != 4){
			printf("perviy int != 4, hz 29\n");
			exit(-1);
		};
		//eax==4

		//lea ebp,[esi+10] 
		//ebp=02e32f20=alloc+38 
		//esi_10=0x02e32f20;
		ebp=esi+0x10; //5 int..

		
		//edi=self->value_02c3f818;
		//ebx=self->value_02c3f844;

		//call 00723220
		//push ebx //ebx=02c3f844 --sohranenniy counter
		//push edi //edi=02c3f818 --ptr on buf
		//push ebp //ebp=02e32eec --alloc_buf+38
		//unpack_7_bit_encoded_to_dword___2(ebp,edi,ebx)
		eax=unpack_7_bit_encoded_to_dword___2(ebp,edi,ebx,selfptr);

		ebx=self->value_02c3f844;
		edi=self->value_02c3f818;

		if (DEBUG) print_buffer("5:",0x40,selfptr);

		//add esp,0c

		//test al,al
		//je jmp ..
		//ne prigaem
		if (eax==0){
			printf("unpack_7_bit_encoded_to_dword___2, return err, hz 30\n");
			exit(-1);
		};


		//mov ecx,[ebp]  //ebp=02e32f20
		//ecx=31
		//ecx=ebp;
		memcpy(&ecx,(char *)ebp,4); //dobivaem znachenie 5 int

		//printf("ecx=%X\n",ecx);
		//exit(-1);

		//mov eax,[ebx]
		//eax=36 //counter
		eax=ebx;
		//eax=self->value_02c3f844;
		//exit(-1);

		//cmp eax,ecx 
		//jb ..
		//if eax<ecx
		//ne prigaem
		if (eax<ecx){
			printf("if ostatok buflen < readed 5 int bytes(0x36<0x31),len sanity check from pkt, err, hz 31\n");
			exit(-1);
		};

		//mov edx, [esp+20]
		//edx=02c3f83c//max len
		//esp_20=var4;
		//edx=esp_20;

		edx=self->value_02c3f83c;
			
		//mov eax,[edx] 
		//eax=0004afc4
		eax=edx;
		//eax=self->value_02c3f83c;

		//cmp eax,ecx
		//jb ..
		//if eax<ecx jmp
		//ne prigaem
		if (eax<ecx){
			printf("if buf max len left < readed from pkt, len check, err,hz 32\n");
			exit(-1);
		};

		//sub eax,ecx //eax=0004afc4//ecx=31
		//eax=0004af93
		eax=eax-ecx;  

		//mov [edx],eax //save some counter
		edx=eax;
		self->value_02c3f83c=eax;

		//mov ecx,[ebp]//ebp=02e32f20
		//ecx=31
		//ecx=ebp;
		memcpy(&ecx,(char *)ebp,4); //dobivaem znachenie 5 int

		//push ecx
		//31

		//call 00714790
		//(mysub_local_alloc_memerr_exception)
		//(novaya !!!)
		//push ecx//31
		eax=mysub_local_alloc_memerr_exception(ecx,selfptr); //heap_alloc_struct alloc
	
		//mov edx,[ebp] //edx=31
		//edx=ebp;
		memcpy(&edx,(char *)ebp,4); //dobivaem znachenie 5 int

		//mov [esi+c],eax //eax=02e2d438=alloc2
		//esi_c=eax;
		//esi_c=self->value_02e2d438;
		//eax=heap_alloc+struct;
		memcpy((char *)esi+0xc,&eax,4); // 4 int ptr on heap_alloc_struct ..

		//mov ecx,[edi] //ecx=02c3f3fb --curr buf ptr
		ecx=edi;
		//ecx=self->value_02c3f818;

		//printf("eax=%X,ecx=%X,edx=%X\n",eax,ecx,edx);

		//push edx //31
		//push ecx //ecx=02c3f3fb --curr buf ptr//self->value_02c3f818
		//push eax //eax=02e2d438 --alloc2//self->value_02e2d438;
		//copy_memory2(alloc2,pkt_buf+0x13,0x31);
		copy_memory2(eax,ecx,edx,selfptr);
		//skopirovali 0x31 v alloc2
		//eax=02e2d438
		//esi=02e32f10
		//edi=02c3f818
		//ebp=02e32f20 alloc+38

		//printf("edx=0x%08X\n",edx);

		//
		if (DEBUG) print_buffer2("3.1:",0x20,selfptr);

//		exit(-1);

		//mov edx,[ebp] //edx=0x31
		//edx=ebp;
		memcpy(&edx,(char *)ebp,4); //dobivaem znachenie 5 int

		//mov esi,[edi] //02c3f3fb - curr buf
		//esi=self->value_02c3f818;
		esi=edi;

		//add esi,edx 
		//esi=02c3f42c --curr buf(after + 0x31 string)
		esi=esi+edx;

		//add esp,10

		//mov [edi],esi  //save curr buff
		edi=esi;
		self->value_02c3f818=esi;

		//mov eax,[ebp] //eax=31
		//eax=ebp;
		memcpy(&eax,(char *)ebp,4); //dobivaem znachenie 5 int

		//mov ecx,[ebx] //ebx-ptr on counter
		//ecx=36
		//ebx=self->value_02c3f844;
		ecx=ebx;

		//pop edi //0x28
		
		//sub ecx,eax
		//ecx=0x05  ostalos byte v pkt buf neobrabotannih
		ecx=ecx-eax;

		//pop esi //esi=02e32f10 alloc+28

		//mov [ebx],ecx // save counter ostavshihsya byte
		ebx=ecx;
		self->value_02c3f844=ecx;

		//pop ebp //ebp=02

		//mov al,1
		eax=1;

		//pop ebx//ebx=02c3f83c

		//retn 10
	
		return eax;
	};
	
    //(ne prigaem)
    //if eax=ebp ..

	//push ebx //ebx=02c3f844

	//add esi,8 //esi=02e32ef0 alloc+8
	//esi=02e32f04 alloc+14+8=alloc+2c
	//esi=02e32f2c
	//self->value_02c3f7fc+8// == int 3
	esi=esi+8;
	//esi=self->value_02c3f7fc+8;

	//edi=self->value_02c3f818;

	//push edi  //EDI=02C3F818
	//push esi  //esi=02e32ef0 alloc+8

	//call 00723220
	//push ebx //ebx=02c3f844 --sohranenniy counter
	//push edi //edi=02c3f818 --ptr on buf
	//push esi //ecx=02e32eec --alloc_buf+8  // int 3 vichislyaem, ranee ono 0
         //ecx=02e32eec --alloc_buf+14+8
	//esi=//esi=02e32f2c alloc_buf+44
	//unpack_7_bit_encoded_to_dword___2(ecx,edi,ebx)
	eax=unpack_7_bit_encoded_to_dword___2(esi,edi,ebx,selfptr);

	if (DEBUG) print_buffer("3:",0x20,selfptr);

	//exit(-1);
	
	//add esp,0c

	//test al,al 
	//if al != 0 jmp
	//prigaem
	if (eax==0){
			printf("unpack_7_bit_encoded_to_dword___2, return error,hz 32\n");
			exit(-1);
	};


	//pop edi //edi=0 //edi=14//edi=3c
	//pop esi //esi=02e32ee8  //02e32efc//esi=02e32f24
	//pop ebp //1//3

	//mov al,1
	eax=1;

	//pop ebx //02c3f83c

	//retn 10

	if (DEBUG) printf("LEAVE mysub_unpack_7_bit_encoded\n");

	return eax;
};




//razmer dannih, razmer buffera kotoriy nujno malloc
//PUSH ECX
//CALL Skype14.00714790
//int mysub_local_alloc_memerr_exception_00714790(uint var1){
//	return 0;
//};






/*
* some new function, case when, first int = 3
*/
//PUSH EDX//value_02c3f844, len
//PUSH EBP//=0
//PUSH EAX//value_02c3f818 buf ptr
//mysub_some_vars_set_math_009278B0(self->value_02c3f818,ebp,self->value_02c3f844);
int __mysub_some_vars_set_math_009278B0(uint var1, uint var2, uint var3,char *selfptr){
		unsigned int eax;
		uint esp_c;

	struct self_s *self;
	self=(struct self_s *)selfptr;

	printf("ENTER mysub_some_vars_set_math_009278B0\n");

	//MOV EAX,DWORD PTR SS:[ESP+C]
	esp_c=var3;
	eax=esp_c;

	//PUSH EBX

	//TEST EAX,EAX
	//JE SHORT Skype14.00927903




	printf("LEAVE mysub_some_vars_set_math_009278B0\n");

	return 0;
};


int __cdecl mysub_some_vars_set_math_009278B0(int a1, unsigned __int8 a2, int a3, char *selfptr)
{
  int result; // eax@1
  int v4; // edx@2
  int v5; // ebx@2
  int v6; // eax@6
  unsigned int v7; // ecx@14
  unsigned int v8; // ecx@16
  char v9; // cl@3
  char v10; // cf@6
  char v11; // zf@8
  unsigned __int8 v12; // cl@9
  char v13; // cf@12
  int v14; // ecx@13

  result = a3;
  if ( a3 )
  {
    v4 = a1;
    LOBYTE(v5) = a2;
    while ( v4 & 3 )
    {
      v9 = *(_BYTE *)v4++;
      if ( !(a2 ^ v9) )
        return v4 - 1;
      --result;
      if ( !result )
        return result;
    }
    v10 = (unsigned int)result < 4;
    v6 = result - 4;
    if ( !v10 )
    {
      v5 = 16843009 * a2;
      do
      {
        v14 = v5 ^ *(_DWORD *)v4;
        v4 += 4;
        if ( ((v14 + 2130640639) ^ ~v14) & 0x81010100 )
        {
          v7 = *(_DWORD *)(v4 - 4);
          LOBYTE(v7) = (_BYTE)v5 ^ (_BYTE)v7;
          if ( !(_BYTE)v7 )
            return v4 - 4;
          BYTE1(v7) ^= v5;
          if ( !BYTE1(v7) )
            return v4 - 3;
          v8 = v7 >> 16;
          if ( !((_BYTE)v5 ^ (_BYTE)v8) )
            return v4 - 2;
          if ( !((_BYTE)v5 ^ BYTE1(v8)) )
            return v4 - 1;
        }
        v13 = (unsigned int)v6 < 4;
        v6 -= 4;
      }
      while ( !v13 );
    }
    v11 = v6 == -4;
    result = v6 + 4;
    if ( !v11 )
    {
      while ( 1 )
      {
        v12 = *(_BYTE *)v4++;
        if ( !((_BYTE)v5 ^ v12) )
          break;
        --result;
        if ( !result )
          return result;
      }
      return v4 - 1;
    }
  }
  return result;
}


/*
*  Allocate buffer for string in 0x41 pkt
*/
//push ecx//31
int mysub_local_alloc_memerr_exception(unsigned int var1, char *selfptr){

		unsigned int eax;
		unsigned int esp_4;
		
		char *heap_alloc_struct;

	struct self_s *self;
	self=(struct self_s *)selfptr;

	if (DEBUG) printf("ENTER mysub_local_alloc_memerr_exception\n");

	//mov eax,[esp+4] //eax=31 dlina

	esp_4=var1;
	eax=esp_4;

	//sub esp,8
	
	//push eax
	//push 0

	//call LocalAlloc//LMEM_FIXED//0x31
	//eax=02e2d438 -- new mem alloc2
	//ecx=7c809a20
	//edx=00150608

	if (DEBUG) printf("str alloc size:0x%08X\n",eax);

	//LocalAlloc(0x31,0);
	heap_alloc_struct=(char *)malloc(eax);
	eax=(unsigned int)heap_alloc_struct;
	self->value_02e2d438=eax;

	//save ptr
	self->heap_alloc_struct_array[self->heap_alloc_struct_count]=heap_alloc_struct;

	//save size
	self->heap_alloc_struct_array_size[self->heap_alloc_struct_count]=esp_4;

	//counted
	self->heap_alloc_struct_count++;

	//sanity check
	if (self->heap_alloc_struct_count>=100){
		printf("more then 100 alloc ptrs (strings) found\n");
		exit(-1);
	};

	//test eax,eax
	//if eax !=0
	//jnz ..
	//prigaem

	if (eax==0){
		printf("mem alloc err2 in mysub_local_alloc_memerr_exception, hz hz\n");
		exit(-1);
	};

	//add esp,8

	//retn
	if (DEBUG) printf("LEAVE mysub_local_alloc_memerr_exception\n");

	return eax;
};








/*
*  obrabativaem/decode-iruem 1 integer v heap_alloc_buf
*
*  init integer with 0, in heap_alloc_buf
*  cikl
*      schitivaem 1 byte, 
*      umenchaem buflen--, 
*      uvelichivaem curr_bufpkt_ptr++,
*      schitanniy byte obrezaem, 
*      krutim,
*      slivaem s tem chto uje est v int v heap_alloc_buf
*      sohranyem v int heap_alloc_buf
*  vihod esli shitanniy byte <=0x80
*/


//push ebx //ebx=02c3f844 --sohranenniy counter
//push edi //edi=02c3f818 --ptr on buf
//push ecx //ecx=02e32eec --alloc_buf+4//self->value_02c3f7fc+4  // 2 int !
//ecx=02e32f00 alloc_buf+18
//ecx=02e32f10 alloc_buf+28
//ecx=02e32f28 alloc_buf+40
//unpack_7_bit_encoded_to_dword___2(ecx,edi,ebx)
int unpack_7_bit_encoded_to_dword___2(unsigned int var1,unsigned int var2,unsigned int var3, char *selfptr){

		unsigned int ebx,edi,esi,eax,ecx,ebp,edx;
		unsigned int esp_10,esp_14,esp_18;
		unsigned char *buf_edi,*buf_edx;

	struct self_s *self;
	self=(struct self_s *)selfptr;

	if (DEBUG) printf("ENTER unpack_7_bit_encoded_to_dword___2\n");

	//push ebx //ebx=02c3f844 

	//mov ebx,[esp+10] 
	//--ebx=02c3f844
	esp_10=var3;
	ebx=esp_10;
	ebx=self->value_02c3f844;

	//push ebp
	//push esi
	//push edi

	//mov edi,[esp+14] 
	//--edi=02e32eec//buf + 4 //perviy byte after 41
	//--edi=02e32ef0//buf + 8 //+8 posle 41
	//edi=02e32f00 alloc_buf+18
	//edi=02e32f04 alloc_buf+1c
	//edi=02e32f14 alloc_buf+2c
	//edi=02e32f20=alloc+38 
	//edi=02e32f28=alloc+40
	//edi=02e32f2c=alloc+44
	esp_14=var1;
	edi=esp_14;
	//edi=self->value_02c3f7fc+4;


	//xor esi,esi
	//esi=0
	esi=0;

	//{init 0ls.}
	//mov [edi],0  --edi = 02c32eec =0 ?
	//     --edi = 02c32ef0 =0 ?
	//edi=0;
	buf_edi=(unsigned char *)edi;
	//buf_edi[0]=0;  //int 2 , initialize
	memcpy(buf_edi,&esi,4);

	//mov eax,[ebx] 
	//-- eax= 42 pkt len ostalos
	//-- eax= 41
	//--eax=3b
	//--3a
	//38//37//4//3
	//eax=self->value_02c3f844;
	eax=ebx;

	//test eax,eax
	//if eax = 0 jmp ..
	//ne prigaem
	if (eax==0){
		printf("buflen=0, error, hz 23\n");
		exit(-1);
	};

	//lea ecx, [eax-1]
	//--ecx=41
	//--ecx=40
	//--ecx=3a
	//39
	//37
	//36
	//3
	//2
	ecx=eax-1;

	//mov [ebx],ecx  --ecx=41,ebx=02c3f844 - save counter
	//      --ecx=40
	//37
	//36
	//3
	//2
	ebx=ecx;
	self->value_02c3f844=ecx;
	
	//je  0072326e
	//ne prigaem


	//mov ebp,[esp+18] --ebp=02c3f818 buf ptr
	esp_18=var2;
	ebp=esp_18;
	//ebp=self->value_02c3f818;


//cikl:
// zahod 2 cikl 2               
// zahod 2 cikl 3
// zahod 2 cikl 4
// zahod 2 cikl 5
//zahod 3 cikl 1
	do {


		//mov eax, [ebp] --eax=02c3f3ef buf. buf+7(8-oy) //01
	    //   --eax=02c3f3f0  buf+9 ??
	    //   --eax=02c3f3f1  buf+10 ??
	    //   --eax=02c3f3f2  buf+11 ??
	    //   --eax=02c3f3f3  buf+12 ??
	    //   --eax=02c3f3f4  buf+13 ?? 
	    //   --eax=02c3f3f6  buf+15 ??
	    //   --eax=02c3f3f7  buf+16 ??
	    //   --eax=02c3f3f9  buf+18 ??
	    //   --eax=02c3f3fa  buf+19 ??
	    //   --eax=02c3f42D  buf+45 ??
	    //   --eax=02c3f42E  buf+46 ??
		eax=self->value_02c3f818;

		//mov ecx, esi --esi=0
		//--ecx=0
		//--ecx=7
		//--ecx=e
		//--ecx=15
		//--ecx=1c
		//
		//--ecx=0
		//...
		ecx=esi;//0
		
		//add esi, 7
		esi=esi+7;

		//mov dl, [eax] --eax=02c3f3ef  --dl = 01 (8-oy byte buf)
 	    //  --eax=02c3f3f0  --dl = 8d (9-iy byte)
		buf_edx=(unsigned char *)self->value_02c3f818;
		edx=buf_edx[0];
        if (DEBUG) printf("READ BYTE=%X\n",edx);
		//printf("edx=%X\n",edx);
		//exit(-1);

		//inc eax 
		//--buf ptr ++  //02c3f3f0 //02c3f3f1//02c3f3f2//02c3f3f3//02c3f3f4//02c3f3f5
		//02c3f3f7//02c3f3f8//02c3f3fa//02c3f3fb//02c3f42e//02c3f42f
		eax++;


		//mov [ebp],eax --ebp=02c3f818
		//--save buf ptr
		ebp=eax;
		self->value_02c3f818=eax;

		//mov al,dl
		//--al=01
		eax=edx;

		//and eax, 7f
		eax=eax & 0x7f;

		//shl eax,cl --cl=0
		//--cl=7
		eax=eax << ecx;

		//mov ecx, [edi] --edi=02c32eec  alloc+4  --ecx=0
	    //   --edi=02c32ef0 alloc+8 --ecx=0
		//ecx=edi;
		buf_edi=(unsigned char *)edi;
		//ecx=buf_edi[0];//=0;  //int 2 
		memcpy(&ecx,buf_edi,4);

		//or ecx,eax 
		//eax=01 //--ecx=01 
		ecx=ecx | eax;

		
		//mov [edi],ecx  --ecx=01
		//--edi=02c32ef0 --ecx=0d 
		//edi=ecx;
		buf_edi=(unsigned char *)edi;
		//buf_edi[0]=ecx;//=0;  //int 2 , data
		memcpy(buf_edi,&ecx,4);

		if (DEBUG) printf("ecx=%X\n",ecx);

		//test dl, 80 --dl=01
		//--dl=8d

		//ne pravilno !
		//if (edx <= 0x80)

		//pravilno
		if (edx < 0x80){
			break;
		};

		//mov eax,[ebx]  //ebx=02c3f844 
		//eax=40
		eax=ebx;
		//eax=self->value_02c3f844;
	
		//lea ecx,[eax-1] //ecx=3f
		//ecx=3e
		ecx=eax-1;

		//mov [ebx],ecx //save cuur counter
		ebx=ecx;
		self->value_02c3f844=ecx;

		//test eax,eax
		//jnz jmp..
		//if eax != 0 jmp ..
		//prigaem v cikl.

	}while(eax!=0);


	//pop edi  //02c3f818
	//pop esi  //02e32ee8//02e32ef0 //02e32efc  //02e32f04  //02e32f10 ////02e32f10
		//02e32f24//02e32f2c
	//pop ebp //ebp=0//0//0/0////02e32f20//0//0

	//mov al,1
	eax=1;

	//pop ebx

	//retn

	if (DEBUG) printf("LEAVE unpack_7_bit_encoded_to_dword___2\n");

	return eax;
};










/*
* Vizivaetsya srazu posle zanuleniya..
* i proevryetsya 1 byte.. kotoriy vsegda 0..
* na chto to.. mem corrupt check.. maybe..
*/
int mysub_call_eax__free(uint var1, char *selfptr){

		unsigned int eax,ecx;

	struct self_s *self;
	self=(struct self_s *)selfptr;

	if (DEBUG) printf("ENTER mysub_call_eax__free()\n");

	//{sravnivaem perviy 3 byte na chto to..hmm.. }
	//jmp 007242c0

	//mov eax,[ecx]  //ecx=02c3ed70
	//ecx=self->value_02c3ed70;
	ecx=var1;
	eax=ecx;

	//eax=0
	//cmp eax,3
	//if eax==3 jmp ..
	if (eax==3){
		printf("memcorrupt, must be 0, hz 16\n");
		exit(-1);
	};

	//cmp eax,4
	//if eax==4 jmp ..
	if (eax==4){
		printf("memcorrupt, must be 0,hz 17\n");
		exit(-1);
	};


	//cmp eax,6
	//if eax==6 jmp ..
	if (eax==6){
		printf("memcorrupt, must be 0,hz 18\n");
		exit(-1);
	};

	//cmp eax,5
	//if eax!=5 jmp 
	//prigaem na vihod normalniy
	if (eax==5){
		printf("memcorrupt, must be 0,hz 19\n");
		exit(-1);
	};

	//ret
	if (DEBUG) printf("LEAVE mysub_call_eax__free()\n");
	
	return 0;
};


/*
*  Zanulili buffer iz var5, 02c3ed70 - 02c3ed80 16 byte  
*/

//{zabili 00-lyamu ecx=02c3ed70 nihera vnutri ne menyalos}
//mysub_no_call_00724060(0,0,0,0,ecx);
int mysub_no_call_00724060(uint var1,uint var2,uint var3,uint var4,uint var5, char *selfptr){

	unsigned int ecx,esi,eax,edx;
	//unsigned int ecx_4,ecx_8,ecx_c;
	unsigned int esp_8,esp_c,esp_10;
	unsigned int esi_8;

	struct self_s *self;
	self=(struct self_s *)selfptr;

	if (DEBUG) printf("ENTER mysub_no_call_00724060\n");

	//push esi
	//mov esi,ecx   //esi=02c3ed70
	ecx=var5;
	//ecx=self->value_02c3ed70;
	esi=ecx;


	//printf("ecx=0x%08X\n",ecx);

//  call 007240a0 {
		//xor eax,eax //eax=0
		eax=0;

		//mov [ecx],eax      //ecx=02c3ed70
		//mov [ecx+4],eax
		//mov [ecx+8],eax
		//mov [ecx+c],eax
		//ecx=eax;

		memset((char *)ecx,0,0x1);

		//printf("ecx=0x%08X\n",ecx);

		/*
		self->value_02c3ed70=eax;
		ecx_4=eax;
		self->value_02c3ed74=eax;
		ecx_8=eax;
		self->value_02c3ed78=eax;
		ecx_c=eax;
		self->value_02c3ed7c=eax;
		*/

		//ret
//  };  // 16 byte zabili 0-yami

	// OTKUDA last 4 byte .. nu pust sdes budet kak init..
	//self->value_02c3ed80=eax;

	//mov eax, [esp+c] //eax=0
	esp_c=var3;
	eax=esp_c;

	//mov ecx, [esp+8]  //ecx=0
	esp_8=var2;
	ecx=esp_8;

	//mov [esi],eax //esi=02c3ed70
	esi=eax;

	//mov [esi],ecx 
	esi=ecx;

	//test eax,eax
	//if eax!=0   .. jmp
	//ne prigaem
	if (eax!=0){
		printf("var3 !=0, hz 14\n");
		exit(-1);
	};

	//mov edx, [esp+10]  //edx=0
	esp_10=var4;
	edx=esp_10;


	//mov eax,esi //eax=02c3ed70
	eax=esi;

	//mov [esi+8], edx
	//esi_8=0; 
	esi_8=edx;

	//pop esi //esi=02c3f7fc

	//retn 10

	if (DEBUG) printf("LEAVE mysub_no_call_00724060\n");

	return 0;
};


/*
*  Copiruem 0x31 iz odnogo buffera v drugoy
*/

//push edx //31
//push ecx //ecx=02c3f3fb --curr buf ptr//self->value_02c3f818
//push eax //eax=02e2d438 --alloc2//self->value_02e2d438;

/*
*  Copiruem 0x14 iz odnogo buffera v drugoy
*/

//push 14
//push ecx // 02c3ed70
//push edx //alloc buf
//copy_memory2(edx,ecx,0x14);
int copy_memory2(unsigned int var1,unsigned int var2,unsigned int var3, char *selfptr){

	unsigned int ebp_8,ebp_c,ebp_10;
	unsigned int esi,ecx,edi,eax,edx;

	uint i;

	struct self_s *self;
	self=(struct self_s *)selfptr;

	if (DEBUG) printf("ENTER copy_memory2\n");

	//push ebp
	//mov ebp,esp
	
	//push edi
	//push esi

	//mov esi,[ebp+c]
	//--esi=02c3ed70 
	ebp_c=var2;
	esi=ebp_c;
	//esi=self->value_02c3ed70;

	//mov ecx,[ebp+10]
	//--ecx=14
	ebp_10=var3;
	ecx=ebp_10;

	//mov edi,[ebp+8]
	//--edi=02e32ee8 alloc
	ebp_8=var1;
	edi=ebp_8;
	//edi=self->value_02c3f7fc;

	//mov eax,ecx -- eax=14
	eax=ecx;

	//mov edx,ecx -- edx=14
	edx=ecx;

	//add eax,esi
	//--eax=02c3ed70+14=02c3ed84
	eax=eax+esi;

	//cmp edi,esi --edi=alloc, esi=02c3ed70
	//jbe jmp..
	//if edi <= esi jmp..
	//ne prigaem
     //printf("edi=%X,esi=%X,eax=%X\n",edi,esi,eax);

	//sravnenie static ptr 0x02c3ed70 and dynamicaly allocated buf ptr.. bred kakoyta, nahuy eto
	//if (edi <= esi){
	//	printf("hz 15\n");
	//	exit(-1);
	//};

	//eax=02c3ed84
	//cmp edi,eax --edi=alloc

	//sravnenie static ptr 0x02c3ed70+0x14 and dynamicaly allocated buf ptr.. bred kakoyta, nahuy eto
	//if edi < eax jmp ..
	//ne prigaem
	//if (edi<eax){
	//	printf("hz 15\n");
	//	exit(-1);
	//};

	
	//edi=self->value_02c3f7fc;
	//test edi,3
	//if edi !=3  jmp
	//ne prigaem
	if (edi==3){
		printf("allocated ptr on buffer = 3, error, hz 16\n");
		exit(-1);
	};


	//ecx=14
	//shr ecx,2 
	//-- ecx=5
	//ecx=31
	//-- ecx=0xc
	ecx=ecx >> 2;

	//edx=14
	//and edx, 3 
	//--edx=0
	edx=edx & 3;

	//cmp ecx, 8
	//jb ..
	//if ecx < 8 jmp
	//prigaem

	if (DEBUG) printf("COPY_MEMORY2: ecx=0x%08X esi=0x%08X\n",ecx,esi);

	
	if (ecx >=8){
		//0x31 ecx >> 2 = 0xc

		///REP MOVS DWORD PTR ES:[EDI],DWORD PTR DS:[ESI]; 
		//ECX=00000000,ESI=02C3F42B, EDI=02E2D468
		memcpy((char *)edi,(char *)esi,var3); // some hacks... 
		
		//printf("ecx posle sdviga >8, drugaya shnyaga,some unexplored copy\n");
		//exit(-1);

		if (DEBUG) printf("LEAVE copy_memory2\n");
		return 0;
	};


	//ecx=0//ecx=5
	//jmp [ecx*4+009270dc]  // jmp 0092710c


	//copiruem byte iz odnogo v drugoe
	//0x14=20 byte copy
	//heap_alloc_buf=(char *)self->value_02c3f7fc;

	//esi=02c3ed70
	//ecx=5
	//mov eax,[esi+ecx*4-14] //[]=02c3ed70
	//eax=0
	//edi=02e32ee8=alloc
	//(filled with 0df0adba)
	//ecx=5
	//mov [edi+ecx*4-14],eax
	//00 00 00 00 0d f0 ad ba ...
	//eax=esi+ecx*4-0x14;
	//heap_alloc_buf[0]=eax;
	//printf("%X %X %X %X\n",heap_alloc_buf[0],heap_alloc_buf[1],heap_alloc_buf[2],heap_alloc_buf[3]);




	for(i=0;i<ecx;i++){
		memcpy(&eax,(char *)esi+i*4,4);
		memcpy((char *)edi+i*4,&eax,4);	
	};



/*


	//eax=self->value_02c3ed70;
	//eax=esi;
	memcpy(&eax,(char *)esi,4);
	memcpy((char *)edi,&eax,4);

	//mov eax,[esi+ecx*4-10] //[]=02c3ed74 //eax=0
	//eax=esi+ecx*4-0x10;
	//mov [edi+ecx*4-10],eax //[]=02e32eec //eax=0
    //eax=self->value_02c3ed74;
	//eax=esi+4;
	memcpy(&eax,(char *)esi+4,4);
	memcpy((char *)edi+0x4,&eax,4);	
	
	//mov eax,[esi+ecx*4-c] 
	//eax=esi+ecx*4-0x0c;
	//mov [edi+ecx*4-c],eax 
    //eax=self->value_02c3ed78;
	//eax=esi+8;
	memcpy(&eax,(char *)esi+0x8,4);
	memcpy((char *)edi+0x8,&eax,4);

	//mov eax,[esi+ecx*4-8] 
	//eax=esi+ecx*4-8;
	//mov [edi+ecx*4-8],eax 
    //eax=self->value_02c3ed7c;
	//eax=esi+0xc;
	memcpy(&eax,(char *)esi+0xc,4);
	memcpy((char *)edi+0xc,&eax,4);

	//mov eax,[esi+ecx*4-4] 
	//mov [edi+ecx*4-4],eax 
	//eax=esi+ecx*4-4;
    //eax=self->value_02c3ed80;
	//eax=esi+0x10;
	memcpy(&eax,(char *)esi+0x10,4);
	memcpy((char *)edi+0x10,&eax,4);


*/



	//podgotovka k eshe onomu ciklu copy 0x14 no on ne ispolzuetsya..

	//lea eax, [ecx*4] //ecx=5
	//eax=14

	eax=ecx*4;

	//esi=02c3ed70
	//add esi,eax
	//esi=ed70+14
	esi=esi+eax;

	//edi=02e32ee8
	//add edi,eax
	//edi=alloc+14
	edi=edi+eax;


	if (edx>0) {
		for(i=0;i<edx;i++){
			memcpy(&eax,(char *)esi+i,1);
			memcpy((char *)edi+i,&eax,1);
		};
	};

	
	//edx=0
	//jmp [edx*4+00927148]  //00927158
//dd 5e08458b {
//pop esi
//}
//pop edi
//leave
//retn


	if (DEBUG) printf("LEAVE copy_memory2\n");

	return 0;
};




/*
*  Nesovsem yasno, vrode nichego ne delaet.. potomu chto, count = 0..
*/ 

//push edx -- 0  //0
//push ecx -- ecx = alloc buf
//push eax -- alloc buf + 0x14
int copy_memory1(unsigned int var1,unsigned int var2,unsigned int var3, char *selfptr){

		unsigned int esi,ecx,eax,edx,edi;
		unsigned int ebp_8;

	struct self_s *self;
	self=(struct self_s *)selfptr;

	if (DEBUG) printf("ENTER copy_memory1\n");

	//push ebp
	//mov ebp,esp

	//push edi
	//push esi

	//mov esi,[ebp+c]
	//--esi=02e32ee8 alloc buf
	esi=var2;

	//mov ecx,[ebp+10]
	//--ecx=0
	ecx=var3;
	
	
	//mov edi,[ebp+8]
	//--edi=02e32efc alloc+14
	edi=var1;


	//mov eax,ecx -- eax =0
	eax=ecx;

	//mov edx,ecx -- edx=0
	edx=ecx;

	//add eax,esi
	//--eax=alloc buf
	eax=eax+esi;
	
	//cmp edi,esi --edi=alloc+14, esi=alloc
	//if edi <= esi jmp..

	if (edi<=esi) {
		printf("ptr var1 menshe ptr var2.. hz 10\n");
		exit(-1);
	};
	//ne prigaem


	//cmp edi,eax --edi=alloc+14, eax=alloc
	//if edi < eax jmp ..
	//ne prigaem
	if (edi<=eax) { 	//negative ptr
			printf("ptr var1 menshe ptr var2 with offset.., hz 11\n");
			exit(-1);
	};
	
	//test edi,3
	//if edi !=3  jmp
	//ne prigaem
	if (edi == 3){
		printf("ptr1==3 ? , hz 12\n");
		exit(-1);
	};

	//shr ecx,2 --ecx=0
	ecx=ecx >> 2;

	//and edx, 3 --edx=0
	//--edx=0
	edx=edx & 3;

	//cmp ecx, 8
	//jb ..
	//if ecx < 8 jmp
	//prigaem
	//ecx=0
	if (ecx >= 8){
		printf("ecx>8 , hz 13\n");
		exit(-1);
	};

	//jmp [ecx*4+009270dc]  // jmp 0092713f

	//jmp [edx*4+00927148]  // jmp 00927158

	//{dd 5e08458b}
	//{
	//mov eax,[ebp+8] //eax=02e32f10


	//ebp_8=0x02e32f10 //alloc+28 ...
	ebp_8=var1+(var1-var2);
	eax=ebp_8;
	//printf("eax=%X\n",eax);
	//neponyatno...nevajno ???


	//pop esi
	//}

	
	//pop edi
	//leave
	//retn
	if (DEBUG) printf("LEAVE copy_memory1\n");

	return 0;
};




/*
*   Vydelenie pamyati
*   Inicializaciya ptr na struct, in self->value_02c3f7fc
*   sanity checks
*/

//push ecx  --size//--ecx=0280
//push esi  -- ptr//--esi=02c3f7fc
int mysub_local_realloc_alloc_getlast_err_exception(unsigned int var1,unsigned int var2, char *selfptr){
	unsigned int esi,edx,eax;

	struct self_s *self;
	self=(struct self_s *)selfptr;

	if (DEBUG) printf("ENTER mysub_local_realloc_alloc_getlast_err_exception\n");

	//mov esi,[esp+10] --esi=02c3f7fc
	esi=var1;
	//esi=self->value_02c3f7fc;

	//mov eax,[esi] --eax=0
	eax=esi;

	//esli znachenie ptr ne NULL, znachit on uje inicializirovan a eto oshibka

	//if eax=0 jmp ..
	//prigaem:
	if (eax!=0){
		printf("esli znachenie ptr ne 0, znachit on uje init-ze a eto err, hz kuda 10\n");
		exit(-1);
	};


	//mov edx,[esp+14] --edx=0x0280
	edx=var2;

	//vydelyaem pamayt

	//push edx
	//push 0 // lmem_fixed
	//call 
	//LocalAlloc(0,edx);
	//????

	self->heap_alloc_buf=(char *)malloc(edx);
	eax=(unsigned int)self->heap_alloc_buf;

	self->heap_alloc_buf_count=0x14;


	//mov [esi],eax --eax=02e32ee8 , --esi=02c3f7fc
	esi=eax;
	self->value_02c3f7fc=eax;

	//pop esi

	//test eax,eax 
	//if eax = 0 jmp .. getlasterror
	if (eax=0) {
		printf("memory alloc error,ptr null after malloc, jmp on getlast error\n");
		exit(-1);
	};

	//add esp,8
	//ret

	if (DEBUG) printf("LEAVE mysub_local_realloc_alloc_getlast_err_exception\n");

	return 0;

};


/*
*    perviy byte posle 0x41 schitaem
*    sohranem posle vsgo sdes: 02c3ed68
*
*/
//push ecx -- 02c3f844//counter
//push eax -- 02c3f818//ptronbuf
//push eax//02c3ed68//sohranenniy schitanniy perviy byte
int unpack_7_bit_encoded_to_dword(uint var1,uint var2,uint var3, char *selfptr){

	unsigned int ebx, edi, esi, eax, ecx, ebp, edx;
	char *buf_eax;

	struct self_s *self;
	self=(struct self_s *)selfptr;

	if (DEBUG) printf("ENTER unpack_7_bit_encoded_to_dword \n");

	//push ebx -- 8
	//mov ebx,[esp+10] 
	//--ebx=02c3f844
	
	self->value_02c3f844=var3;
	ebx=self->value_02c3f844;

	//push ebp
	//push esi
	//push edi

	//mov edi,[esp+14] 
	//--edi=02c3ed68
	
    //link kak sdelat ..

	self->value_02c3ed68=var1;//unused..
	edi=self->value_02c3ed68;



	//xor esi,esi
	esi=0;

	//mov [edi],0  --edi = 02c3ed68
	self->value_02c3ed68=0;
	edi=0;
	//var1=0;

    //printf("edi=%X,self->value_02c3ed68=%X\n",edi,self->value_02c3ed68);

	//mov eax,[ebx] 
	//-- eax= 44 pkt len ostalos
	//eax=ebx;
	eax=self->value_02c3f844;

	
	//test eax,eax
	if (eax==0){
			printf("konchilsya buffer,smth like terra nova here, jmp hz kuda\n");
			exit(-1);
	};


	//lea ecx, [eax-1]
	//--ecx=43
	ecx=eax-1;

	//mov [ebx],ecx  --ecx=43,ebx=02c3f844 - counter
	self->value_02c3f844=ecx;
	ebx=ecx;


	//mov ebp,[esp+18] --ebp=02c3f818 buf ptr
    self->value_02c3f818=var2;
	ebp=self->value_02c3f818;

	do{
		//mov eax, [ebp] --eax=02c3f3ed buf.
		eax=ebp;

		//mov ecx, esi --esi=0
		//--ecx=0
		ecx=esi;

		//add esi, 7
		//--esi=7
		esi=esi+7;

		//mov dl, [eax] --eax=02c3f3ed
		//--dl = 04 (5-iy byte buf)
		buf_eax=(char *)eax;
		edx=buf_eax[0];//ptr

		//printf("edx=%X\n",edx);

		//inc eax 
		//--buf ptr ++
		eax++;

		//mov [ebp],eax --ebp=02c3f818
		//--save buf ptr
		self->value_02c3f818=eax;
		ebp=eax;

		//mov al,dl
		//--al=04
		eax=edx;

		//and eax, 7f
		//--eax = 04 & 7f = 04
		eax=eax & 0x7f;


		//shl eax,cl --cl=0
		eax=eax << ecx;

		//mov ecx, [edi] --edi=02c3ed68
		//--ecx=0
		ecx=self->value_02c3ed68;
		ecx=edi;

		//or ecx,eax --ecx=0 ,eax=04
		//--ecx=04
		ecx=ecx | eax;


		//mov [edi],ecx  --ecx=04
		self->value_02c3ed68=ecx; //sohranyaem sdes..
		edi=ecx;

	    //printf("ecx=%X\n",ecx);

		//test dl, 80 --dl=04
		//if (edx < 0x80){
				//na vihod
		//};
	}while(edx >= 0x80);  //if byte reaed from buf...

//vihod;

	//pop edi
	//pop esi 
	//pop ebp
	//mov al,1
	eax=1;

	//pop ebx
	//retn

	if (DEBUG) printf("LEAVE unpack_7_bit_encoded_to_dword \n");

	return eax;

};



//
// new function, called if first integer == 1
//
int mygen_no_call_00927FF0(uint eax,uint ecx,uint edx,uint *eax11,uint *ecx11,uint *edx11, char *selfptr){
	//uint ecx,edx,eax;
	uint ecx1,edx1,eax1;
	
	struct self_s *self;
	self=(struct self_s *)selfptr;
	
	//cmp     cl, 40h

	//Jump if not below
	//jnb     short loc_92800A
	if (ecx >= 0x40) {
		//xor     eax, eax
		eax=0;
		
		//xor     edx, edx
		edx=0;

		//alter retn
		*edx11=edx;
		*eax11=eax;
		*ecx11=ecx;
		return eax;
	};

	//cmp     cl, 20h
	//jnb     short loc_928000
	if (ecx >= 0x20) {
		//mov     edx, eax
		edx=eax;

		//xor     eax, eax
		eax=0;

		//and     cl, 1Fh
		ecx=ecx & 0x1f;

		//shl     edx, cl
		edx=edx << ecx;

		//alter retn
		*edx11=edx;
		*eax11=eax;
		*ecx11=ecx;
		return eax;
	};


	edx1=edx;
	eax1=eax;
	ecx1=ecx;
	//shld    edx, eax, cl
	__asm { 
		mov edx, edx1;
		mov eax, eax1;
		mov ecx, ecx1;
		shld    edx, eax, cl;
		mov edx1, edx;
		mov eax1, eax;
		mov ecx1, ecx;
	};
	edx=edx1;
	eax=eax1;
	ecx=ecx1;

	//shl     eax, cl
	eax=eax << ecx;


	//alter retn
	*edx11=edx;
	*eax11=eax;
	*ecx11=ecx;

	//retn
	return eax;
};




