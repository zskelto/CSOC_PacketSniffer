/*
 * Zachary Skelton
 * Clemson CSOC
 * sniffer.c
 *
 * Purpose: Extracts the payloads of TCP and UDP messages.
 **/

#include <stdio.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

void my_packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){

	const struct ip *IPHeader;
	char sourceIP[INET_ADDRSTRLEN];
	struct ether_header *eth_header;
	const u_char *ip_header, *tcp_header, *payload;

	int ethernet_header_length = 14;
	int tcp_header_length;
	int ip_header_length;
	int payload_length;
	
	u_char protocol;

	eth_header = (struct ether_header *) packet;
	if(ntohs(eth_header->ether_type) != ETHERTYPE_IP){
		return;
	}

	ip_header = packet + ethernet_header_length;
	ip_header_length = ((*ip_header) & 0x0F);
	ip_header_length *= 4;
	//Fetches source ip address
	IPHeader = (struct ip*) ip_header;
	inet_ntop(AF_INET, &(IPHeader->ip_src), sourceIP, INET_ADDRSTRLEN);
	
	protocol = *(ip_header + 9);
	if(protocol != IPPROTO_TCP){
		return;
	}

	tcp_header = ip_header + ip_header_length;
	tcp_header_length = (((*(tcp_header + 12)) & 0xF0) >> 4)*4;
	
	payload_length = header->caplen-(ethernet_header_length + ip_header_length + tcp_header_length);
	payload = packet + ethernet_header_length + ip_header_length + tcp_header_length;
	
	if(payload_length > 0){
		printf("%s: ",sourceIP);
		const u_char *temp_pointer = payload;
		int byte_count = 0;
		while(byte_count++ < payload_length){
			printf("%c",*temp_pointer);
			temp_pointer++;
		}
		printf("\n");
	}
	return;
}

int main(int argc, char **argv){
	//VM uses enp0s3
	char *device = "enp0s3";
	char error_buffer[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	//Bytes to capture from each packet.
	int snapshot_length = 1024;
	//How many packets to capture.
	int total_packet_count = 200;
	u_char *my_arguments = NULL;

	handle = pcap_open_live(device, snapshot_length, 0, 10000, error_buffer);
	pcap_loop(handle, total_packet_count, my_packet_handler, my_arguments);
	return 0;
}

