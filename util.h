#include <cstdio>
#include <pcap.h>
#include <pthread.h>
#include "mac.h"
#include "ip.h"

#include <fstream>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>

struct IpHdr
{
    uint8_t dum0[2];
    uint16_t total_length;   /* total length */
    uint8_t dum1[5];
    uint8_t ip_p;            /* protocol */
    uint8_t dum2[2];
    
    uint32_t ip_src;	      /* src ip */
    uint32_t ip_dst;         /* dst ip */
};

void IntIpChar(char* tar, uint32_t value){
	sprintf(tar, "%u.%u.%u.%u",
		(value & 0xFF000000) >> 24,
		(value & 0x00FF0000) >> 16,
		(value & 0x0000FF00) >> 8,
		(value & 0x000000FF));
}


#pragma pack(push, 1)


#pragma pack(pop)

#define ARP_SIZE 42

bool get_ip(char* dev, char* ip) {
	struct ifreq ifr;
	int sfd = socket(AF_INET, SOCK_DGRAM, 0),ret;
	if(sfd < 0){
		printf("Fail to get interface MAC address - socket() failed - %m\n");
		return false;
	}

	strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	ret = ioctl(sfd, SIOCGIFADDR, &ifr);
	if(ret < 0){
		printf("Fail to get interface MAC address - ioctl(SIOCSIFHWADDR) failed - %m\n");
		close(sfd);
		return false;
	}
	
	inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2, ip, 4*Ip::SIZE);
	close(sfd);
	return true;
}

bool get_mac(char* dev, uint8_t* mac) {
	struct ifreq ifr;
	int sfd = socket(AF_INET, SOCK_DGRAM, 0),ret;
	if(sfd < 0){
		printf("Faile to get interface MAC address - socket() failed - %m\n");
		return false;
	}

	strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	ret = ioctl(sfd, SIOCGIFHWADDR, &ifr);
	if(ret < 0){
		printf("Fail to get interface MAC address - ioctl(SIOCSIFHWADDR) failed - %m\n");
		close(sfd);
		return false;
	}

	memcpy(mac, ifr.ifr_hwaddr.sa_data, Mac::SIZE);
	close(sfd);
	return true;
}