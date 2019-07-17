#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#define HEADER_SIZE 54


typedef struct c_packet {
    uint8_t d_mac[6];
    uint8_t s_mac[6];
    uint16_t type;
    uint8_t pad1[2];
    uint16_t size;
    uint16_t id;
    uint8_t pad2[2];
    uint8_t ttl;
    uint8_t protocol;
    uint16_t header_checksum;
    uint8_t s_ip[4];
    uint8_t d_ip[4];
    uint16_t s_port;
    uint16_t d_port;
    uint8_t pad3[10];
    uint16_t win_size;
    uint16_t checksum;
    uint16_t urgent;
    uint8_t data[0x400];
}c_packet; // custom packet structure

void print_mac(uint8_t*mac) {
	printf("%02X:%02X:%02X:%02X:%02X:%02X\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void print_ip(uint8_t*ip) {
	printf("%u.%u.%u.%u\n", ip[0], ip[1], ip[2], ip[3]);
}

void print_port(uint16_t port) {
	printf("%u\n", port);
}
void usage() {
    printf("syntax: pcap_test <interface>\n");
    printf("sample: pcap_test wlan0\n");
}

uint16_t my_ntohs(uint16_t num) {
    return ((num & 0xff00) >> 8) + ((num & 0xff) << 8);
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
	usage();
	return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
	fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
	return -1;
    }

    while (true) {
	struct pcap_pkthdr* header;
	const u_char*data;
	c_packet* packet;
	int res = pcap_next_ex(handle, &header, &data);
	int loop;
	if (!res) continue;
	if (res == -1 || res == -2) break;
	packet = (c_packet*)data;
	if(packet -> protocol != 6) {
	    puts("ONLY TCP...");
	    continue;
	}
	printf("=========================================\n");
	printf("%u bytes captured\n", header->caplen);
	printf("S_MAC : ");
	print_mac(packet->s_mac);
	printf("D_MAC : ");
	print_mac(packet->d_mac);
	printf("S_IP : ");
	print_ip(packet->s_ip);
	printf("D_IP : ");
	print_ip(packet->d_ip);
	printf("S_PORT : ");
	print_port(my_ntohs(packet->s_port));
	printf("D_PORT : ");
	print_port(my_ntohs(packet->d_port));
	packet->size = my_ntohs(packet->size);
	packet->size += 0xe;
	if(packet->size - HEADER_SIZE == 0) {
	    puts("This Packet don't have data");
	    continue;
	}

	else {
	    printf("data : [ ");
	    /*
	    if(packet->size - HEADER_SIZE > 10) loop = 10;
	    else loop = packet->size - HEADER_SIZE;
	    */
	    loop = (packet->size - HEADER_SIZE > 10) ? 10 : packet->size - HEADER_SIZE;
	    for(int i = 0; i < loop; ++i) {
		printf("%X ", packet->data[i]);
	    }
	    puts("]");
	}
    }

    pcap_close(handle);
    return 0;
}
