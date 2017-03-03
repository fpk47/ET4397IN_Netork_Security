#include "parser.h"
#include "packet.h"
#include "message.h"

static char text[100];

static PCAP_FILE* p_current_pcap_file = NULL;
static PCAP_FILE_GLOBAL_HEADER *p_current_pcap_file_global_header;
static uint32_t current_index = 0;

static uint32_t parse_ethernet_header( uint8_t *p_data, ETHERNET_HEADER *p_ethernet_header, uint32_t current_index );
static uint32_t parse_ip_4_header( uint8_t *p_data, IP_4_HEADER *p_ip_4_header, uint32_t current_index );
static uint32_t parse_udp_header( uint8_t *p_data, UDP_HEADER *p_udp_header, uint32_t current_index );
static uint32_t parse_tcp_header( uint8_t *p_data, TCP_HEADER *p_tcp_header, uint32_t current_index );
static uint32_t parse_dns_header( uint8_t *p_data, DNS_HEADER *p_dns_header, uint32_t current_index );
static uint32_t parse_rr_query_entry( uint8_t *p_data, RR_QUERY_ENTRY *p_rr_query_entry, uint32_t current_index );

static uint8_t getBit( uint8_t value, uint8_t index ){
	return ( ( value >> index )  & 0x01) ;
}

static void swap_variable( uint8_t *p_data, uint32_t size ){
	uint8_t *p_temp = (uint8_t *) malloc( size );

	for ( int i = 0; i < size; i++ ){
		p_temp[size - i - 1] = p_data[i];
	}

	for ( int i = 0; i < size; i++ ){
		p_data[i] = p_temp[i];
	}

	free( p_temp );
}

void set_current_pcap_file( PCAP_FILE* p_pcap_file ){
	p_current_pcap_file = p_pcap_file;
	current_index = PCAP_FILE_GLOBAL_HEADER_SIZE;
	p_current_pcap_file_global_header = (PCAP_FILE_GLOBAL_HEADER*) p_pcap_file->p_data;

	print_debug( "parser.c: set_current_pcap_file() --> STARTING...\n" );
	sprintf( text, "parser.c: set_current_pcap_file() --> get_size_pcap_entry_header() == %d\n", get_size_pcap_entry_header( p_current_pcap_file_global_header ) );
	print_debug( text );
	return;
}

PACKET* get_next_pcap_file_packet( void ){
	uint8_t *p_data = p_current_pcap_file->p_data;

	if ( p_current_pcap_file == NULL ){
		print_warning( "parser.c: get_next_pcap_file_packet() --> p_current_pcap_file == NULL\n" );
		return NULL;
	}

	PCAP_FILE_ENTRY_HEADER *p_pcap_file_entry_header = (PCAP_FILE_ENTRY_HEADER*) &p_data[current_index];
	if (  p_pcap_file_entry_header->incl_len != p_pcap_file_entry_header->orig_len ){
		print_warning( "parser.c: get_next_pcap_file_packet() --> incl_len != orig_len\n" );
		return NULL;
	}

	if ( current_index >= p_current_pcap_file->size - 1 ){
		print_info( "parser.c: get_next_pcap_file_packet() --> EOF\n" );
		return NULL;
	}

	current_index += get_size_pcap_entry_header( p_current_pcap_file_global_header );
	uint32_t size = p_pcap_file_entry_header->incl_len;

	PACKET *p_packet = init_packet_uint8_t( size, &p_data[current_index] );
	parse_packet( p_packet );
    current_index += size;

	return p_packet;
}

void parse_packet( PACKET *p_packet){
	uint32_t rr_entry_index = 0;
	uint32_t temp_index = 0;
	uint8_t *p_data = p_packet->p_data;

	temp_index = parse_ethernet_header( p_data, &(p_packet->ethernet_header), temp_index );

	if ( get_ethernet_type( p_packet ) != TYPE_IP4 ){
		print_warning( "parser.c: get_next_pcap_file_packet() --> no IP4, abort\n" );
		return;
	}

	temp_index = parse_ip_4_header( p_data, &(p_packet->ip_4_header), temp_index );

	if ( is_udp_packet( p_packet ) ){
		temp_index = parse_udp_header( p_data, &(p_packet->udp_header), temp_index );
	} else if ( is_tcp_packet( p_packet ) ){
		temp_index = parse_tcp_header( p_data, &(p_packet->tcp_header), temp_index );
	} else{
		print_warning( "parser.c: get_next_pcap_file_packet() --> no UDP or TCP, abort\n" );
		return;
	}
	
	if ( !is_dns_packet( p_packet) ){
		print_info( "parser.c: get_next_pcap_file_packet() --> port_dst != 53 and port_src != 53\n" );
		return;
	}

	temp_index = parse_dns_header( p_data, &(p_packet->dns_header), temp_index );

	if ( get_dns_number_of_queries( p_packet ) != 1 ){
		print_info( "parser.c: get_next_pcap_file_packet() --> #queries != 1\n" );
		return;
	}

	temp_index = parse_rr_query_entry( p_data, &(p_packet->rr_query_entry), temp_index );
}

static uint32_t parse_ethernet_header( uint8_t *p_data, ETHERNET_HEADER *p_ethernet_header, uint32_t current_index ){
	memcpy( p_ethernet_header->mac_dst, &p_data[  current_index + 0 ], 6 );
	memcpy( p_ethernet_header->mac_src, &p_data[  current_index + 6 ], 6 );
	memcpy( &(p_ethernet_header->type), &p_data[  current_index + 12 ], 2 );
	swap_variable( (uint8_t *) &(p_ethernet_header->type), 2 );

	return current_index + get_ethernet_header_size();
}

static uint32_t parse_ip_4_header( uint8_t *p_data, IP_4_HEADER *p_ip_4_header, uint32_t current_index ){
	memcpy( &(p_ip_4_header->IHL), &p_data[ current_index + 0 ], 1 );
	p_ip_4_header->IHL &= 0x0F;

	memcpy( &(p_ip_4_header->protocol), &p_data[ current_index +  9 ], 1 );
	memcpy( &(p_ip_4_header->ip_4_src), &p_data[ current_index + 12 ], 4 );
	memcpy( &(p_ip_4_header->ip_4_dst), &p_data[ current_index + 16 ], 4 );

	return current_index + get_ip_4_header_size( p_ip_4_header );
}

static uint32_t parse_udp_header( uint8_t *p_data, UDP_HEADER *p_udp_header, uint32_t current_index ){
	memcpy( &(p_udp_header->port_dst), &p_data[ current_index +  0 ], 2 );
	swap_variable( (uint8_t *) &(p_udp_header->port_dst), 2 );

	memcpy( &(p_udp_header->port_src), &p_data[ current_index +  2 ], 2 );
	swap_variable( (uint8_t *) &(p_udp_header->port_src), 2 );

	memcpy( &(p_udp_header->length), &p_data[ current_index + 4 ], 2 );
	swap_variable( (uint8_t *) &(p_udp_header->length), 2 );

	memcpy( &(p_udp_header->checksum), &p_data[ current_index + 6 ], 2 );
	swap_variable( (uint8_t *) &(p_udp_header->checksum), 2 );
	
	return current_index + get_udp_header_size();
}


static uint32_t parse_tcp_header( uint8_t *p_data, TCP_HEADER *p_tcp_header, uint32_t current_index ){
	memcpy( &(p_tcp_header->port_src), &p_data[ current_index + 0 ], 2 );
	swap_variable( (uint8_t *) &(p_tcp_header->port_src), 2 );

	memcpy( &(p_tcp_header->port_dst), &p_data[ current_index + 2 ], 2 );
	swap_variable( (uint8_t *) &(p_tcp_header->port_dst), 2 );

	memcpy( &(p_tcp_header->data_offset), &p_data[ current_index + 12 ], 1 );
	p_tcp_header->data_offset >>= 4;

	return current_index + get_tcp_header_size( p_tcp_header );
}

static uint32_t parse_dns_header( uint8_t *p_data, DNS_HEADER *p_dns_header, uint32_t current_index ){
	memcpy( &(p_dns_header->identification), &p_data[ current_index + 0 ], 2 );
	swap_variable( (uint8_t *) &(p_dns_header->identification), 2 );

	memcpy( &(p_dns_header->QR), &p_data[ current_index + 2 ], 1 );
	p_dns_header->QR = getBit( p_dns_header->QR, 0 );

	memcpy( &(p_dns_header->opcode), &p_data[ current_index + 2 ], 1 );
	(p_dns_header->opcode) <<= 1;
	(p_dns_header->opcode) >>= 4;

	memcpy( &(p_dns_header->AA), &p_data[ current_index + 2 ], 1 );
	p_dns_header->AA = getBit( p_dns_header->AA, 5 );

	memcpy( &(p_dns_header->TC), &p_data[ current_index + 2 ], 1 );
	p_dns_header->TC = getBit( p_dns_header->TC, 6 );

	memcpy( &(p_dns_header->RD), &p_data[ current_index + 2 ], 1 );
	p_dns_header->RD = getBit( p_dns_header->RD, 7 );

	memcpy( &(p_dns_header->RA), &p_data[ current_index + 3 ], 1 );
	p_dns_header->RA = getBit( p_dns_header->RA, 0 );

	memcpy( &(p_dns_header->Z), &p_data[ current_index + 3 ], 1 );
	p_dns_header->Z = getBit( p_dns_header->Z, 1 );

	memcpy( &(p_dns_header->AD), &p_data[ current_index + 2 ], 1 );
	p_dns_header->AD = getBit( p_dns_header->AD, 2 );

	memcpy( &(p_dns_header->CD), &p_data[ current_index + 3 ], 1 );
	p_dns_header->CD = getBit( p_dns_header->CD, 3 );

	memcpy( &(p_dns_header->rcode), &p_data[ current_index + 3 ], 1 );
	(p_dns_header->rcode) &= 0x0F;

	memcpy( &(p_dns_header->query_count), &p_data[ current_index + 4 ], 2 );
	swap_variable( (uint8_t *) &(p_dns_header->query_count), 2 );

	memcpy( &(p_dns_header->answer_count), &p_data[ current_index + 6 ], 2 );
	swap_variable( (uint8_t *) &(p_dns_header->answer_count), 2 );

	memcpy( &(p_dns_header->authority_count), &p_data[ current_index + 8 ], 2 );
	swap_variable( (uint8_t *) &(p_dns_header->authority_count), 2 );

	memcpy( &(p_dns_header->additional_count), &p_data[ current_index + 10 ], 2 );
	swap_variable( (uint8_t *) &(p_dns_header->additional_count), 2 );

	return current_index + get_dns_header_size();
}


uint32_t parse_rr_query_entry( uint8_t *p_data, RR_QUERY_ENTRY *p_rr_query_entry, uint32_t current_index ){
	uint32_t size = 0;

	do{
		p_rr_query_entry->name[size] = p_data[ current_index + size ];
		size++;
	} while ( p_data[ current_index + size ] != 0 );
	
	p_rr_query_entry->name[size] = p_data[ current_index + size ];
	size++;

	memcpy( &(p_rr_query_entry->rr_type), &p_data[ current_index + size + 0 ], 2 );
	swap_variable( (uint8_t *) &(p_rr_query_entry->rr_type), 2 );
	size += 2;

	memcpy( &(p_rr_query_entry->rr_class), &p_data[ current_index + size + 2 ], 2 );
	swap_variable( (uint8_t *) &(p_rr_query_entry->rr_class), 2 );
	size += 2;

	return size;
}

/*
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
	uint16_t question_count;
	uint16_t answer_count;
	uint16_t authority_count;
	uint16_t additional_count;
} DNS_HEADER;
*/

