#include "arp.h"

#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <linux/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
//addition...
#include <ctype.h>
#include <arpa/inet.h>

//You can fill the following functions or add other functions if needed. If not, you needn't write anything in them.  
void set_hard_type(struct ether_arp *packet, unsigned short int type)
{
	packet->ea_hdr.ar_hrd = type;
}
void set_prot_type(struct ether_arp *packet, unsigned short int type)
{
	packet->ea_hdr.ar_pro = type;
}
void set_hard_size(struct ether_arp *packet, unsigned char size)
{
	packet->ea_hdr.ar_hln = size;
}
void set_prot_size(struct ether_arp *packet, unsigned char size)
{
	packet->ea_hdr.ar_pln = size;
}
void set_op_code(struct ether_arp *packet, short int code)
{
	packet->ea_hdr.ar_op = code;
}

void set_sender_hardware_addr(struct ether_arp *packet, char *address)
{
	unsigned int temp[6];
	sscanf(address, "%x:%x:%x:%x:%x:%x", &temp[0], &temp[1], &temp[2], &temp[3], &temp[4], &temp[5]);
	for(int i = 0; i < 6; i++){
		packet->arp_sha[i] = (unsigned char)temp[i];
	}
}
void set_sender_protocol_addr(struct ether_arp *packet, char *address)
{
	unsigned int temp[4];
	sscanf(address, "%u.%u.%u.%u", &temp[0], &temp[1], &temp[2], &temp[3]);
	for(int i = 0; i < 4; i++){
		packet->arp_spa[i] = (unsigned char)temp[i];
	}

}
void set_target_hardware_addr(struct ether_arp *packet, char *address)
{
	unsigned int temp[6];
	sscanf(address, "%x:%x:%x:%x:%x:%x", &temp[0], &temp[1], &temp[2], &temp[3], &temp[4], &temp[5]);
	for(int i = 0; i < 6; i++){
		packet->arp_tha[i] = (unsigned char)temp[i];
	}
}
void set_target_protocol_addr(struct ether_arp *packet, char *address)
{
	unsigned int temp[4];
	sscanf(address, "%u.%u.%u.%u", &temp[0], &temp[1], &temp[2], &temp[3]);
	for(int i = 0; i < 4; i++){
		packet->arp_tpa[i] = (unsigned char)temp[i];
	}
}

char* get_target_protocol_addr(struct ether_arp *packet)
{
	// if you use malloc, remember to free it.
	char* result = (char*)malloc(sizeof(char) * 15);
	sprintf(result, "%u.%u.%u.%u", packet->arp_tpa[0], packet->arp_tpa[1], packet->arp_tpa[2], packet->arp_tpa[3]);
	return result;

}
char* get_sender_protocol_addr(struct ether_arp *packet)
{
	// if you use malloc, remember to free it.
	char* result = (char*)malloc(sizeof(char) * 15);
	sprintf(result, "%u.%u.%u.%u", packet->arp_spa[0], packet->arp_spa[1], packet->arp_spa[2], packet->arp_spa[3]);
	return result;

}
char* get_sender_hardware_addr(struct ether_arp *packet)
{
	// if you use malloc, remember to free it.
	char* result = (char*)malloc(sizeof(char) * 17);
	sprintf(result, "%02x:%02x:%02x:%02x:%02x:%02x", packet->arp_sha[0], packet->arp_sha[1], packet->arp_sha[2], packet->arp_sha[3], packet->arp_sha[4], packet->arp_sha[5]);
	return result;

}
char* get_target_hardware_addr(struct ether_arp *packet)
{
	// if you use malloc, remember to free it.
	char* result = (char*)malloc(sizeof(char) * 17);
	sprintf(result, "%02x:%02x:%02x:%02x:%02x:%02x", packet->arp_tha[0], packet->arp_tha[1], packet->arp_tha[2], packet->arp_tha[3], packet->arp_tha[4], packet->arp_tha[5]);
	return result;

}
void print_usage(){
	printf("Format:\n");
	printf("1) ./arp -l -a\n");
	printf("2) ./arp -l <filter_ip_address>\n");
	printf("3) ./arp -q <query_ip_address>\n");
	printf("4) ./arp <fake_mac_address> <target_ip_address>\n");
	exit(1);
}
int IsValidMAC(const char* str){
	for(int i = 0; i < 17; i++){
		if(i % 3 != 2 && !isxdigit(str[i])){
			return 0;
		}
		else if(i % 3 == 2 && str[i] != ':'){
			return 0;
		}
	}
	return 1;
}
int IsValidIP(const char* str){
	struct sockaddr_in sa;
	int result = inet_pton(AF_INET, str, &(sa.sin_addr));
	if(result == 1){
		return 1;
	}
	return 0;
}

