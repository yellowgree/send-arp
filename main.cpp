#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/ether.h>

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)


struct libnet_ethernet_hdr
{
    u_int8_t  ether_dhost[ETHER_ADDR_LEN];/* destination ethernet address */
    u_int8_t  ether_shost[ETHER_ADDR_LEN];/* source ethernet address */
    u_int16_t ether_type;                 /* protocol */
};

void usage() {
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
}

int main(int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return -1;
	}

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Failed to create socket");
        return 1;
    }

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	EthArpPacket packet;




    // 인터페이스 이름 설정
    char ifname[] = "eth0";

    // 인터페이스 정보 구조체 생성S
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("Failed to get MAC address");
        return 1;
    }

    // MAC 주소 출력
    unsigned char *mac = (unsigned char*) ifr.ifr_hwaddr.sa_data;
    printf("My MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    char ipstr[40];
    int s;
    s = socket(AF_INET, SOCK_DGRAM, 0);
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

    if (ioctl(s, SIOCGIFADDR, &ifr) < 0) {
        printf("Error");
    } else {
        inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2,ipstr,sizeof(struct sockaddr));
        printf("myOwn IP Address is %s\n", ipstr);
    }


    typedef struct {
        char* dev_;
    } Param;

    Param param = {
        .dev_ = NULL
    };





    //Get target mac..
    pcap_t* pcap = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }



    while (true)
    {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            //printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        struct libnet_ethernet_hdr *eth_hdr = (struct libnet_ethernet_hdr*) packet;
        if (ntohs(eth_hdr->ether_type) != ETHERTYPE_IP) continue;
        printf("ethernet_src MAC:%s\n",  ether_ntoa(eth_hdr->ether_shost));
    }

    pcap_close(pcap);




    /*
     *
     *

    packet.eth_.dmac_ = Mac();   //dst ether mac
    packet.eth_.smac_ = Mac(ifr.ifr_hwaddr.sa_data);   // src ether mac
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = Mac(ifr.ifr_hwaddr.sa_data);     //src mac
    packet.arp_.sip_ = htonl(Ip()); //sender ip
    packet.arp_.tmac_ = Mac();     //dst mac
    packet.arp_.tip_ = htonl(Ip()); //target ip

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

	pcap_close(handle);


    */
}
