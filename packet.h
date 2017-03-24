#ifndef PACKET_H
#define PACKET_H

#define PRINT_MODE_FULL FALSE
#define NUMBER_OF_RR_ENTRIES 100

#define PACKET_TEXT_SIZE 200

#include "general_includes.h"
#include "crc32.h"

#define TYPE_RADIO_TAP_BEACON 0x80
#define TYPE_RADIO_TAP_AUTHENTICATION 0xB0
#define TYPE_RADIO_TAP_ACK 0xD1
#define TYPE_RADIO_TAP_ASSOCIATION_REQUEST 0x00
#define TYPE_RADIO_TAP_ASSOCIATION_RESPONS 0x10
#define TYPE_RADIO_TAP_DATA 0x02
#define TYPE_RADIO_TAP_DISASSOCIATION 0xA0

#define TYPE_RADIO_TAP 1
#define TYPE_ETHERNET 2
#define TYPE_IP4 0x0800
#define TYPE_IP6 0x86DD
#define TYPE_ARP 0x0806
#define TYPE_UDP 0x11
#define TYPE_TCP 0x06

#define TYPE_ARP_REQUEST 0x0001
#define TYPE_ARP_REPLY 0x0002

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

typedef struct radio_tap_header
{
	uint16_t length;
	uint64_t time;
	uint8_t type;
	uint8_t to_DS;
	uint8_t from_DS;

	uint8_t src_address[6];
	uint8_t dst_address[6];
	uint8_t BSSID[6];
	uint8_t transmission_station_address[6];
	uint8_t receiving_station_address[6];
} RADIO_TAP_HEADER;

typedef struct ethernet_header
{
	uint8_t MAC_dst[6];
	uint8_t MAC_src[6];
	uint16_t type;
} ETHERNET_HEADER;

typedef struct IP4_header
{
	uint8_t IP4_dst[4];
	uint8_t IP4_src[4];
	uint8_t protocol;
	uint8_t IHL;
} IP4_HEADER;

typedef struct ARP_header
{
	uint16_t hardware_type;
	uint16_t protocol_type;
	uint8_t hardware_size;
	uint8_t protocol_size;
	uint16_t opcode;
	uint8_t MAC_src[6];
	uint8_t IP4_src[4];
	uint8_t MAC_dst[6];
	uint8_t IP4_dst[4];
	uint8_t message_bus_type;
} ARP_HEADER;

typedef struct UDP_header
{
	uint16_t port_dst;
	uint16_t port_src;
	uint16_t length;
	uint16_t checksum;
} UDP_HEADER;

typedef struct TCP_header
{
	uint16_t port_dst;
	uint16_t port_src;
	uint8_t data_offset;
} TCP_HEADER;

typedef struct DNS_header
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
	uint32_t unique_ID;
	uint32_t used;
	char text[ PACKET_TEXT_SIZE ];
	uint32_t size;
	uint32_t type;
	uint8_t *p_data;

	RADIO_TAP_HEADER radio_tap_header;
	ETHERNET_HEADER ethernet_header;
	ARP_HEADER ARP_header;
	IP4_HEADER IP4_header;
	UDP_HEADER UDP_header;
	TCP_HEADER TCP_header;
	DNS_HEADER DNS_header;

	RR_QUERY_ENTRY rr_query_entry;
	RR_ENTRY *p_rr_entries[NUMBER_OF_RR_ENTRIES];
} PACKET;

void update_CFS( PACKET *p_packet );

uint8_t* get_data( PACKET *p_packet );
uint32_t get_size( PACKET *p_packet );

uint8_t* get_MAC_broadcast( void );
uint32_t compare_MAC( uint8_t* p_MAC_1, uint8_t* p_MAC_2 );
uint32_t compare_IP4( uint8_t* p_IP4_1, uint8_t* p_IP4_2 );
void init_packet( void );

uint32_t is_used( PACKET *p_packet );
void set_used( PACKET *p_packet );

uint8_t is_radio_tap_packet( PACKET *p_packet );
uint8_t is_ethernet_packet( PACKET *p_packet );
uint8_t has_IP4_header( PACKET *p_packet );
uint8_t has_IP6_header( PACKET *p_packet );
uint8_t has_ARP_header( PACKET *p_packet );
uint8_t has_UDP_header( PACKET *p_packet );
uint8_t has_TCP_header( PACKET *p_packet );
uint8_t has_DNS_header( PACKET *p_packet );

RADIO_TAP_HEADER* get_radio_tap_header( PACKET *p_packet );
ETHERNET_HEADER* get_ethernet_header( PACKET *p_packet );
ARP_HEADER* get_ARP_header( PACKET *p_packet );
IP4_HEADER* get_IP4_header( PACKET *p_packet );
UDP_HEADER* get_UDP_header( PACKET *p_packet );
TCP_HEADER* get_TCP_header( PACKET *p_packet );
DNS_HEADER* get_DNS_header( PACKET *p_packet );
RR_QUERY_ENTRY* get_rr_query_entry( PACKET *p_packet );

uint32_t get_radio_tap_header_size( RADIO_TAP_HEADER *p_radio_tap_header );
uint32_t get_ethernet_header_size( void );
uint32_t get_ARP_header_size( void );
uint32_t get_IP4_header_size( IP4_HEADER *p_IP4_header );
uint32_t get_UDP_header_size( void );
uint32_t get_TCP_header_size( TCP_HEADER *p_TCP_header );
uint32_t get_DNS_header_size( void );
uint32_t get_rr_entry_size( RR_ENTRY *p_rr_entry );

uint32_t is_ARP_request( PACKET *p_packet );
uint32_t is_ARP_reply( PACKET *p_packet );

char* get_type_name( PACKET *p_packet );
uint32_t get_type( PACKET *p_packet );
uint32_t get_unique_ID( PACKET *p_packet );

uint32_t has_radio_tap_src_address( PACKET *p_packet );
uint32_t has_radio_tap_dst_address( PACKET *p_packet );
uint32_t has_radio_tap_BSSID( PACKET *p_packet );
uint32_t has_radio_tap_transmission_station_address( PACKET *p_packet );
uint32_t has_radio_tap_receiving_station_address( PACKET *p_packet );

uint8_t* get_radio_tap_src_address( PACKET *p_packet );
uint8_t* get_radio_tap_dst_address( PACKET *p_packet );
uint8_t* get_radio_tap_BSSID( PACKET *p_packet );
uint8_t* get_radio_tap_transmission_station_address( PACKET *p_packet );
uint8_t* get_radio_tap_receiving_station_address( PACKET *p_packet );
uint8_t get_radio_tap_to_DS( PACKET *p_packet );
uint8_t get_radio_tap_from_DS( PACKET *p_packet );
uint8_t get_radio_tap_type( PACKET *p_packet );
char* get_radio_tap_type_name( PACKET *p_packet );
uint32_t get_radio_tap_length( PACKET *p_packet );
uint64_t get_radio_tap_time( PACKET *p_packet );

char* get_ARP_opcode_name( PACKET *p_packet );
uint8_t get_ARP_opcode( PACKET *p_packet );
uint8_t* get_ARP_MAC_src( PACKET *p_packet );
uint8_t* get_ARP_IP4_src( PACKET *p_packet );
uint8_t* get_ARP_MAC_dst( PACKET *p_packet );
uint8_t* get_ARP_IP4_dst( PACKET *p_packet );

uint16_t get_ethernet_type( PACKET* p_packet );
char* get_ethernet_type_name( PACKET* p_packet );
uint8_t get_IP4_protocol( PACKET* p_packet );
char* get_IP4_protocol_name( PACKET* p_packet );
uint8_t get_IP4_IHL( PACKET *p_packet );

uint32_t get_DNS_number_of_queries( PACKET* p_packet );
uint32_t get_DNS_number_of_answers( PACKET* p_packet );
uint32_t get_DNS_number_of_authorities( PACKET* p_packet );
uint32_t get_DNS_number_of_additionals( PACKET* p_packet );

uint16_t get_TCP_port_src( PACKET *p_packet );
uint16_t get_TCP_port_dst( PACKET *p_packet );

void set_TCP_port_src( PACKET *p_packet, uint16_t TCP_port_src );
void set_TCP_port_dst( PACKET *p_packet, uint16_t TCP_port_dst );

void set_IP4_src( PACKET *p_packet, uint8_t *p_IP4_src );
void set_IP4_dst( PACKET *p_packet, uint8_t *p_IP4_dst );

uint8_t* get_IP4_src( PACKET *p_packet );
uint8_t* get_IP4_dst( PACKET *p_packet );

void set_MAC_src( PACKET *p_packet, uint8_t *p_MAC_src );
void set_MAC_dst( PACKET *p_packet, uint8_t *p_MAC_dst );

uint8_t* get_ethernet_MAC_src( PACKET *p_packet );
uint8_t* get_ethernet_MAC_dst( PACKET *p_packet );

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
void set_packet_text( PACKET* p_packet, char *p_text );
char* get_packet_text( PACKET* p_packet );
PACKET* clone_packet( PACKET* p_packet );
uint32_t compare_packets( PACKET* p_packet_1, PACKET* p_packet_2 );
void free_rr_entry( RR_ENTRY *p_rr_entry );

#endif