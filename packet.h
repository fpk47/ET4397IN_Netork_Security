#ifndef PACKET_H
#define PACKET_H

#define PRINT_MODE_FULL FALSE
#define NUMBER_OF_RR_ENTRIES 100

#include "general_includes.h"

#define TYPE_IP4 0x0800
#define TYPE_UDP 0x11
#define TYPE_TCP 0x06

#define TYPE_QUERY 0x01
#define TYPE_ANSWER 0x02
#define TYPE_AUTHORITY 0x03
#define TYPE_ADDITIONAL 0x04

#define CLASS_RR_IN 1
#define CLASS_RR_CS 2
#define CLASS_RR_CH 3
#define CLASS_RR_HS 4

#define TYPE_RR_A_STAR 255
#define TYPE_RR_AAAA 28
#define TYPE_RR_A 1
#define TYPE_RR_NS 2
#define TYPE_RR_CNAME 5
#define TYPE_RR_SOA 6
#define TYPE_RR_PTR 12
#define TYPE_RR_MX 15
#define TYPE_RR_TXT 16

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
	uint8_t type;
	char name[100];
	uint16_t rr_type;
	uint16_t rr_class;
	uint32_t TTL;
	uint16_t length;
	uint8_t *p_rr_data;
} RR_ENTRY;

typedef struct rr_query_entry
{
	char name[100];
	uint16_t rr_type;
	uint16_t rr_class;
} RR_QUERY_ENTRY;

typedef struct packet{
	uint32_t size;
	uint8_t *p_data;

	ETHERNET_HEADER ethernet_header;
	IP_4_HEADER ip_4_header;
	UDP_HEADER udp_header;
	TCP_HEADER tcp_header;
	DNS_HEADER dns_header;

	RR_QUERY_ENTRY rr_query_entry;
	RR_ENTRY *p_rr_entries[NUMBER_OF_RR_ENTRIES];
} PACKET;

uint8_t is_udp_packet( PACKET *p_packet );
uint8_t is_tcp_packet( PACKET *p_packet );
uint8_t is_dns_packet( PACKET *p_packet );

ETHERNET_HEADER *get_ethernet_header( PACKET *p_packet );
IP_4_HEADER *get_IP_4_header( PACKET *p_packet );
UDP_HEADER* get_UDP_header( PACKET *p_packet );
TCP_HEADER* get_TCP_header( PACKET *p_packet );
DNS_HEADER* get_DNS_header( PACKET *p_packet );
RR_QUERY_ENTRY* get_rr_query_entry( PACKET *p_packet );

uint32_t get_ethernet_header_size();
uint32_t get_ip_4_header_size( IP_4_HEADER *p_ip_4_header );
uint32_t get_udp_header_size();
uint32_t get_tcp_header_size( TCP_HEADER *p_tcp_header );
uint32_t get_dns_header_size();
uint32_t get_rr_entry_size( RR_ENTRY *p_rr_entry );

uint16_t get_ethernet_type( PACKET* p_packet );
uint32_t get_dns_number_of_queries( PACKET* p_packet );
uint32_t get_dns_number_of_answers( PACKET* p_packet );
uint32_t get_dns_number_of_authorities( PACKET* p_packet );
uint32_t get_dns_number_of_additionals( PACKET* p_packet );

char* get_rr_entry_type_name( RR_ENTRY *p_rr_entry );

uint32_t get_rr_entry_rr_type( RR_ENTRY *p_rr_entry );
char* get_rr_entry_rr_class_name( RR_ENTRY *p_rr_entry );
char* get_rr_entry_rr_type_name( RR_ENTRY *p_rr_entry );

char* get_rr_query_entry_rr_class_name( RR_QUERY_ENTRY *p_rr_query_entry );
char* get_rr_query_entry_rr_type_name( RR_QUERY_ENTRY *p_rr_query_entry );

void print_packet( PACKET* p_packet );

RR_ENTRY* init_rr_entry( void );

PACKET* init_packet_u_char( uint32_t size, const u_char *data );
PACKET* init_packet_uint8_t( uint32_t size, uint8_t *data );
void free_packet( PACKET* p_packet );
void free_rr_entry( RR_ENTRY *p_rr_entry );

#endif