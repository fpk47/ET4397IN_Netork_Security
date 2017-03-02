#ifndef PACKET_H
#define PACKET_H

#define PRINT_MODE_FULL FALSE

#include "general_includes.h"

#define TYPE_IP4 0x0800
#define TYPE_UDP 0x11
#define TYPE_TCP 0x06

typedef struct ethernet_header
{
	uint8_t mac_dst[6];
	uint8_t mac_src[6];
	uint16_t type;
} ETHERNET_HEADER;

typedef struct ip_4_header
{
	uint8_t ip_4_dst[4];
	uint8_t ip_4_src[4];
	uint8_t protocol;
	uint8_t IHL;
} IP_4_HEADER;

typedef struct udp_header
{
	uint16_t port_dst;
	uint16_t port_src;
	uint16_t length;
	uint16_t checksum;
} UDP_HEADER;

typedef struct tcp_header
{
	uint16_t port_dst;
	uint16_t port_src;
	uint8_t data_offset;
} TCP_HEADER;

typedef struct dns_header
{
	uint16_t identification;
	uint8_t QR;
	uint8_t opcode;
	uint8_t AA;
	uint8_t TC;
	uint8_t RD;
	uint8_t RA;
	uint8_t Z;
	uint8_t AD;
	uint8_t CD;
	uint8_t rcode;
	uint16_t query_count;
	uint16_t answer_count;
	uint16_t authority_count;
	uint16_t additional_count;
} DNS_HEADER;

typedef struct rr_entry
{
	char name[100];
	uint16_t type;
	uint16_t rr_class;
	uint32_t TTL;
	uint16_t length;
	uint8_t *p_r_data;
} RR_ENTRY;

typedef struct packet{
	uint32_t size;
	uint8_t *p_data;

	ETHERNET_HEADER ethernet_header;
	IP_4_HEADER ip_4_header;
	UDP_HEADER udp_header;
	TCP_HEADER tcp_header;
	DNS_HEADER dns_header;

	RR_ENTRY *rr_entries[100];
} PACKET;

uint8_t is_udp_packet( PACKET *p_packet );
uint8_t is_tcp_packet( PACKET *p_packet );
uint8_t is_dns_packet( PACKET *p_packet );

uint32_t get_ethernet_header_size();
uint32_t get_ip_4_header_size( IP_4_HEADER *p_ip_4_header );
uint32_t get_udp_header_size();
uint32_t get_tcp_header_size( TCP_HEADER *p_tcp_header );
uint32_t get_dns_header_size();

void print_packet( PACKET* p_packet );

PACKET* init_packet_u_char( uint32_t size, const u_char *data );
PACKET* init_packet_uint8_t( uint32_t size, uint8_t *data );
void free_packet( PACKET* p_packet );

#endif