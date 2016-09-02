// prepare 0x42 slot requests from supernodes
//

//#include "short_types.h"

#include "skype/skype_basics.h"
#include "skype/skype_rc4.h"


int make_tcp_reqslot_prepare(u16 seqnum, u16 req_slot, u16 req_slot_size, char *send_pkt) {
	u8 result[0x1000];
	int result_len;
	u8 header[0x100];
	int header_len=5;
	int send_len;


	skype_thing	mythings[] = {
		{00, 00, req_slot, 0x00},
		{00, 05, req_slot_size, 0x00},
	};
	int mythings_len=2;

	skype_list		list = {&list, mythings, mythings_len, mythings_len};

	result_len=main_pack_into(&list, result, sizeof(result)-1 );

	show_memory(result,result_len,"packed42:");
	main_unpack42(result,result_len);

	header_len=encode_to_7bit(header, result_len+2, header_len);


	// pkt start bytes
	send_len = 0;
	send_pkt[0]=0x18;
	send_len+=1;

	// seqnum
	seqnum=_bswap16(seqnum);
	memcpy(send_pkt+send_len,(char *)&seqnum,2);
	seqnum=_bswap16(seqnum);
	send_len+=2;


	// pkt size
	memcpy(send_pkt+send_len,header,header_len);
	send_len+=header_len;

	// cmd 
	send_pkt[send_len]=0x32;
	send_len++;

	// seqnum
	seqnum--;
	seqnum=_bswap16(seqnum);
	memcpy(send_pkt+send_len,(char *)&seqnum,2);
	seqnum=_bswap16(seqnum);
	send_len+=2;

	// 42 data
	memcpy(send_pkt+send_len,result,result_len);
	send_len+=result_len;

	return send_len;
};



/*
u8 test[]=
"\x42\x34\x36\x3A\xD3\x1E"
;

{
00-00: 80 02 00 00
00-05: 05 00 00 00
}


===
setup1pkt
Len: 0x00000034
18 85 D4 08 32 85 D3 42 34 36 3A D3 1E 18 85 D6 
 08 32 85 D5 42 34 52 59 F8 1E 18 85 D8 08 32 85 
 D7 42 34 4E 67 90 1E 18 85 DA 08 32 85 D9 42 32 
 40 F6 4F F7 
{
00-00: 80 02 00 00
00-05: 05 00 00 00
}
{
00-00: F2 02 00 00
00-05: 05 00 00 00
}
{
00-00: E2 02 00 00
00-05: 05 00 00 00
}
{
00-00: 2D 00 00 00
00-05: 05 00 00 00
}
===

*/
