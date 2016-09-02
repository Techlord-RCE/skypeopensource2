//
// Socket communication
//

#include <stdio.h>
#include <stdlib.h>

#include <winsock.h>  

int sock;
int connected=0;

////////////////////////////////////////////////
// sockets related                            //
////////////////////////////////////////////////

//unified udp communication, send buffer, and place retrived data into result.
int udp_talk(char *remoteip, unsigned short remoteport, char *buf, int len, char *result){
	int sock, ret, addrlen;
	struct sockaddr_in addr;
	WSADATA wsaDATA;
	char tmpbuf[1024];
	fd_set rfds;
	struct timeval tv;

	tv.tv_sec=5;
	tv.tv_usec=0;

	if (WSAStartup(MAKEWORD(2,0),&wsaDATA)!=0){
		printf("WSAStartup error. Error: %d\n",WSAGetLastError());
	};

	sock=socket(PF_INET,SOCK_DGRAM,IPPROTO_UDP);
	if (sock==-1) {
		printf("Socket creation error\n");
		exit(-1);
	};

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr=inet_addr(remoteip);
	addr.sin_port=htons(remoteport);

	ret=sendto(sock, buf, len, 0, (struct sockaddr*)&addr, sizeof(addr));
	if (ret < 0) {
		printf("Sendto error\n");
		exit(-1);
	};

	addrlen=sizeof(addr);
	memset(tmpbuf,0,sizeof(tmpbuf));

    FD_ZERO(&rfds);
	FD_SET(sock, &rfds);
	
	select(sock+1, &rfds, NULL, NULL, &tv);

    if(FD_ISSET(sock, &rfds)){
		if (ret=recvfrom(sock, tmpbuf, 1023, 0, (struct sockaddr*)&addr, &addrlen)){
			memcpy(result, tmpbuf, ret);
		};
		if (ret<0){
			printf("Recvfrom error\n");
			exit(-1);
		};
	}else{ 
			//timeout
			return 0;
	};

	shutdown(sock,2);
	closesocket(sock);
	

	return ret;
};



//unified tcp communication, send buffer, and place retrived data into result.
int tcp_talk(char *remoteip, unsigned short remoteport, char *buf, int len, char *result,int need_close) {
	int ret;
	struct sockaddr_in addr;
	WSADATA wsaDATA;
	char tmpbuf[0x10000];
	int cnt=0;
	int cnt2=0;
	


	if (connected==0) {

		if (WSAStartup(MAKEWORD(2,0),&wsaDATA)!=0){
			printf("WSAStartup error. Error: %d\n",WSAGetLastError());
		};

		sock=socket(PF_INET,SOCK_STREAM,IPPROTO_TCP);
		if (sock==-1) {
			printf("Socket creation error\n");
			exit(-1);
		};

		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr=inet_addr(remoteip);
		addr.sin_port=htons(remoteport);

		ret=connect(sock, (struct sockaddr*)&addr, sizeof(addr));
		if (ret < 0) {
			printf("Connect failed\n");
			exit(-1);
		};

		connected=1;
	};
	

	ret=send(sock, buf, len, 0);
	if (ret < 0) {
		printf("Send error\n");
		exit(-1);
	};

	memset(tmpbuf,0,sizeof(tmpbuf));
	cnt=recv(sock, tmpbuf, 0x10000, 0);
	memcpy(result,tmpbuf,cnt);
	if (cnt<=5){
		memset(tmpbuf,0,sizeof(tmpbuf));
		cnt2=recv(sock, tmpbuf, 0x10000, 0);
		memcpy(result+cnt,tmpbuf,cnt2);
		cnt=cnt+cnt2;
	};

/*	
	memset(tmpbuf,0,sizeof(tmpbuf));
	while ( (cnt=recv(sock, tmpbuf, 1023, 0)) > 0 ){
		memcpy(result+cnt,tmpbuf,cnt);
		cnt=cnt+strlen(tmpbuf);
		memset(tmpbuf,0,sizeof(tmpbuf));
	};
*/

	if (cnt<0){
		printf("Recv error\n");
		exit(-1);
	};


	if (need_close) {
		shutdown(sock,2);
		closesocket(sock);
		connected=0;
	};
	

	return cnt;
};





//unified tcp communication, send buffer, and place retrived data into result.
int tcp_talk_recv(char *remoteip, unsigned short remoteport, char *result, int need_close) {
	int ret;
	struct sockaddr_in addr;
	WSADATA wsaDATA;
	char tmpbuf[0x10000];
	int cnt=0;
	


	if (connected==0) {

		if (WSAStartup(MAKEWORD(2,0),&wsaDATA)!=0){
			printf("WSAStartup error. Error: %d\n",WSAGetLastError());
		};

		sock=socket(PF_INET,SOCK_STREAM,IPPROTO_TCP);
		if (sock==-1) {
			printf("Socket creation error\n");
			exit(-1);
		};

		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr=inet_addr(remoteip);
		addr.sin_port=htons(remoteport);

		ret=connect(sock, (struct sockaddr*)&addr, sizeof(addr));
		if (ret < 0) {
			printf("Connect failed\n");
			exit(-1);
		};

		connected=1;
	};


	memset(tmpbuf,0,sizeof(tmpbuf));
	cnt=recv(sock, tmpbuf, 0x10000, 0);
	memcpy(result,tmpbuf,cnt);


	if (cnt<0){
		printf("Recv error\n");
		exit(-1);
	};


	if (need_close) {
		shutdown(sock,2);
		closesocket(sock);
		connected=0;
	};
	

	return cnt;
};



//unified tcp communication, send buffer, and place retrived data into result.
int tcp_talk_recv2(char *result) {
	char tmpbuf[0x10000];
	int cnt=0;
	int cnt2=0;
	

	memset(tmpbuf,0,sizeof(tmpbuf));
	cnt=recv(sock, tmpbuf, 0x10000, 0);
	memcpy(result,tmpbuf,cnt);
	if (cnt<=5){
		memset(tmpbuf,0,sizeof(tmpbuf));
		cnt2=recv(sock, tmpbuf, 0x10000, 0);
		memcpy(result+cnt,tmpbuf,cnt2);
		cnt=cnt+cnt2;
	};


	if (cnt<0){
		printf("Recv error\n");
		exit(-1);
	};


	return cnt;
};



//unified tcp communication, send buffer, and place retrived data into result.
int tcp_talk_tmp(char *remoteip, unsigned short remoteport, char *buf, int len, char *result,int need_close) {
	int ret;
	struct sockaddr_in addr;
	WSADATA wsaDATA;
	char tmpbuf[0x10000];
	int cnt=0;
	int cnt2=0;
	


	if (connected==0) {

		if (WSAStartup(MAKEWORD(2,0),&wsaDATA)!=0){
			printf("WSAStartup error. Error: %d\n",WSAGetLastError());
		};

		sock=socket(PF_INET,SOCK_STREAM,IPPROTO_TCP);
		if (sock==-1) {
			printf("Socket creation error\n");
			exit(-1);
		};

		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr=inet_addr(remoteip);
		addr.sin_port=htons(remoteport);

		ret=connect(sock, (struct sockaddr*)&addr, sizeof(addr));
		if (ret < 0) {
			printf("Connect failed\n");
			exit(-1);
		};

		connected=1;
	};
	

	ret=send(sock, buf, len, 0);
	if (ret < 0) {
		printf("Send error\n");
		exit(-1);
	};

	memset(tmpbuf,0,sizeof(tmpbuf));
	cnt=recv(sock, tmpbuf, 0x10000, 0);
	memcpy(result,tmpbuf,cnt);
	printf("RECV CNT: %d\n",cnt);

	if (cnt<=5){
		memset(tmpbuf,0,sizeof(tmpbuf));
		cnt2=recv(sock, tmpbuf, 0x10000, 0);
		memcpy(result+cnt,tmpbuf,cnt2);
		cnt=cnt+cnt2;
	};


	if (cnt<0){
		printf("Recv error\n");
		exit(-1);
	};


	if (need_close) {
		shutdown(sock,2);
		closesocket(sock);
		connected=0;
	};
	

	return cnt;
};



//unified tcp communication, send buffer, and place retrived data into result.
int tcp_talk_send(char *buf, int len) {
	int ret;
	int cnt=0;
	int cnt2=0;

	ret=send(sock, buf, len, 0);
	if (ret < 0) {
		printf("Send error\n");
		exit(-1);
	};

	return ret;
};


