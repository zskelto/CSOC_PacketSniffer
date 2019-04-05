#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>

int main(void){

	struct sockaddr_in addr;

	/*
	 * AF_INET: IPv4
	 * SOCK_DGRAM: UDP Socket
	 * 0: Only one form of datagram service
	 * */
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	if(s < 0){
		perror("Failed to create socket.");
		return 0;
	}
	
	memset((char *)&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(8080);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);

	if(bind(s, (struct sockaddr *)&addr, sizeof(addr))){
		perror("Failed to bind.");
		return 0;
	}

	

	return 0;
}

