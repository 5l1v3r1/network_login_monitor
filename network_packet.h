
#ifndef _NETWORK_PACKET_H__
#define _NETWORK_PACKET_H__

#include <winsock.h>

#pragma comment (lib,"ws2_32")

struct ether_header
{
	u_int8_t  ether_dhost[6];      /* destination eth addr */
	u_int8_t  ether_shost[6];      /* source ether addr    */
	u_int16_t ether_type;          /* packet type ID field */
};

struct iphead
{
	u_int8_t ip_header_length:4,ip_version:4;
	u_int8_t ip_tos;
	u_int16_t ip_length;
	u_int16_t ip_id;
	u_int16_t ip_off;
	u_int8_t ip_ttl;
	u_int8_t ip_protocol;
	u_int16_t ip_checksum;
	struct in_addr ip_souce_address;
	struct in_addr ip_destination_address;
};

struct udphead
{
	u_int16_t udp_source_port;
	u_int16_t udp_destinanion_port;
	u_int16_t udp_length;
	u_int16_t udp_checksum;
};

#endif
