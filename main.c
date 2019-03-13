#include <netinet/if_ether.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include "arp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
//addition...
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
/*
 * Change "enp2s0f5" to your device name (e.g. "eth0"), when you test the program.
 * If you don't know your device name, you can use "ifconfig" command on Linux.
 */
#define DEVICE_NAME "enp2s0f5"
#define MAC_BCAST_ADDR {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
#define IPLEN 4
/*
 * You have to open two socket to handle this program.
 * One for input , the other for output.
 */
int main(int argc, char* argv[])
{
	int sockfd_recv = 0, sockfd_send = 0;
	struct sockaddr_ll sa;
	struct ifreq req;
	struct in_addr myip;
	//
	int option;
	struct sockaddr saddr;
	int saddr_size;
	struct arp_packet buffer;
	char mymac[17];
	unsigned char src_mac_addr[ETH_ALEN], dst_mac_addr[ETH_ALEN], bcast_mac_addr[ETH_ALEN] = MAC_BCAST_ADDR;


	if(getuid() != 0){
		printf("Error: You must be root to use this tool!\n");
		exit(1);
	}
	else{
		if(argc != 3 || (strcmp(argv[1], "-l") != 0 && strcmp(argv[1], "-q") != 0 && IsValidMAC(argv[1]) == 0)){
			print_usage();
		}
		else{
			if(strcmp(argv[1], "-l") == 0){
				if(strcmp(argv[2], "-a") != 0 && IsValidIP(argv[2]) == 0){
					print_usage();
				}
				else if(strcmp(argv[2], "-a") == 0){
					option = 1;
				}
				else{
					option = 2;
				}
			}
			else if(strcmp(argv[1], "-q") == 0){
				if(IsValidIP(argv[2]) == 0){
					print_usage();
				}
				else{
					option = 3;
				}
			}
			else if(IsValidMAC(argv[1]) == 1){
				if(IsValidIP(argv[2]) == 0){
					print_usage();
				}
				else{
					//option = 4;
				}
			}
		}
	}
	// Open a recv socket in data-link layer.
	if((sockfd_recv = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
	{
		perror("open recv socket error");
		exit(1);
	}

	/*
	 * Use recvfrom function to get packet.
	 * recvfrom( ... )
	 */
	printf("[ ARP sniffer and spoof program ]\n");
	if(option == 1 || option == 2){
		printf("### ARP sniffer mode ###\n");
		while(1){
			int data_size = recvfrom(sockfd_recv, &buffer, sizeof(buffer), 0, &saddr, (socklen_t *)&saddr_size);
			if(data_size < 0){
				printf("recvfrom error!\n");
				exit(1);
			}
			//use ntohs to convert byte order from host order to network order
			if(ntohs(buffer.eth_hdr.ether_type) == ETHERTYPE_ARP){
				if(ntohs(buffer.arp.ea_hdr.ar_op) == ARPOP_REQUEST){
					//convert unsigned char to char[], ip1 for target ip, ip2 for sender ip
					char* ip1 = get_target_protocol_addr(&(buffer.arp));
					char* ip2 = get_sender_protocol_addr(&(buffer.arp));
					if(option == 1 || (option == 2 && strcmp(argv[2], ip1) == 0)){
						printf("Get ARP packet - Who has %s?\t\tTell %s\n", ip1, ip2);
					}
					free(ip1);
					free(ip2);
				}
				/*else if(ntohs(buffer.arp.ea_hdr.ar_op) == ARPOP_REPLY){
					char* ip1 = get_target_protocol_addr(&(buffer.arp));
                                        char* ip2 = get_sender_protocol_addr(&(buffer.arp));
					char* mac = get_sender_hardware_addr(&(buffer.arp));
                                        if(option == 1 || (option == 2 && (strcmp(argv[2], ip1) == 0 || strcmp(argv[2], ip2) == 0))){
                                                printf("%s reply to %s\tMAC : %s\n", ip2, ip1, mac);
                                        }
					free(mac);
                                        free(ip1);
                                        free(ip2);
				}*/
			}
		}
	}


	// Open a send socket in data-link layer.
	if((sockfd_send = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
	{
		perror("open send socket error");
		exit(sockfd_send);
	}
	/*
	 * Use ioctl function binds the send socket and the Network Interface Card.
`	 * ioctl( ... )
	 */
	if(option == 3){
		printf("### ARP query mode ###\n");
		memset(&req, 0, sizeof(req));
		//network interface name
		strcpy(req.ifr_name, DEVICE_NAME);
		//get network interface ip
		if(ioctl(sockfd_send, SIOCGIFADDR, &req) == -1){
			printf("Error in getting ip\n");
			exit(1);
		}
		myip = ((struct sockaddr_in*)&req.ifr_addr)->sin_addr;
		//get network interface card address
		if(ioctl(sockfd_send, SIOCGIFHWADDR, &req) == -1){
			printf("Error in getting mac\n");
			exit(1);
		}
		memcpy(src_mac_addr, req.ifr_hwaddr.sa_data, ETH_ALEN);
		//use sprintf to convert mac addr from unsigned char* to char*
		sprintf(mymac, "%02x:%02x:%02x:%02X:%02x:%02x", (unsigned char)req.ifr_hwaddr.sa_data[0], (unsigned char)req.ifr_hwaddr.sa_data[1], (unsigned char)req.ifr_hwaddr.sa_data[2], (unsigned char)req.ifr_hwaddr.sa_data[3], (unsigned char)req.ifr_hwaddr.sa_data[4], (unsigned char)req.ifr_hwaddr.sa_data[5]);
		// Fill the parameters of the sa.
		//interface number
		sa.sll_ifindex = if_nametoindex(DEVICE_NAME);
		//protocol family, should be AF_PACKET
		sa.sll_family = PF_PACKET;
		//physical-layer protocol
		sa.sll_protocol = htons(ETH_P_ARP);
		//length of addr
		sa.sll_halen = ETHER_ADDR_LEN;
		//fill the ethernet header
		memset(&buffer, 0, sizeof(buffer));
		buffer.eth_hdr.ether_type = htons(ETHERTYPE_ARP);
		memcpy(buffer.eth_hdr.ether_dhost, bcast_mac_addr, ETH_ALEN);
		memcpy(buffer.eth_hdr.ether_shost, src_mac_addr, ETH_ALEN);
		//fill arp data
		set_hard_type(&(buffer.arp), htons(ARPHRD_ETHER));
		set_prot_type(&(buffer.arp), htons(ETHERTYPE_IP));
		set_hard_size(&(buffer.arp), ETH_ALEN);
		set_prot_size(&(buffer.arp), (unsigned char)IPLEN);
		set_op_code(&(buffer.arp), htons(ARPOP_REQUEST));
		//use inet_ntoa to convert ip address from struct in_addr to char*
		set_sender_protocol_addr(&(buffer.arp), inet_ntoa(myip));
		set_sender_hardware_addr(&(buffer.arp), mymac);
		set_target_protocol_addr(&(buffer.arp), argv[2]);
		set_target_hardware_addr(&(buffer.arp), "00:00:00:00:00:00");
		/*
	 	 * use sendto function with sa variable to send your packet out
	 	 * sendto( ... )
	 	 */
		int n = sendto(sockfd_send, &buffer, sizeof(buffer), 0, (struct sockaddr*)&sa, sizeof(struct sockaddr_ll));
		if(n < 0){
			perror("sendto error");
			exit(1);
		}
		//get reply of ARP request above
		memset(&buffer, 0, sizeof(buffer));
		while(1){
			int data_size = recvfrom(sockfd_recv, &buffer, sizeof(buffer), 0, &saddr, (socklen_t *)&saddr_size);
       			if(data_size < 0){
        			printf("recvfrom error!\n");
	                	exit(1);
        		}
	        	if(ntohs(buffer.eth_hdr.ether_type) == ETHERTYPE_ARP){
				if(ntohs(buffer.arp.ea_hdr.ar_op) == ARPOP_REPLY){
                			char* ip1 = get_target_protocol_addr(&(buffer.arp));
                        		char* ip2 = get_sender_protocol_addr(&(buffer.arp));
                        		char* mac = get_sender_hardware_addr(&(buffer.arp));
                        		if(strcmp(ip2, argv[2]) == 0){
						printf("MAC address of %s is %s\n", ip2, mac);
					}
                        		free(mac);
                	        	free(ip1);
        	                	free(ip2);
					break;
	                	}

			}
		}
	}
	close(sockfd_send);
	close(sockfd_recv);
	return 0;
}
