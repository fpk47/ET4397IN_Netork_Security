#include "parser.h"
#include "packet.h"
#include "message.h"
#include "tools.h"

static char text[100];

static PCAP_FILE* p_current_pcap_file = NULL;
static PCAP_FILE_GLOBAL_HEADER *p_current_pcap_file_global_header;
static uint32_t current_index = 0;

static uint32_t parse_ethernet_header( uint8_t *p_data, ETHERNET_HEADER *p_ethernet_header, uint32_t current_index );
static uint32_t parse_IP4_header( uint8_t *p_data, IP4_HEADER *p_IP4_header, uint32_t current_index );
static uint32_t parse_ARP_header( uint8_t *p_data, ARP_HEADER *p_ARP_header, uint32_t current_index );
static uint32_t parse_UDP_header( uint8_t *p_data, UDP_HEADER *p_UDP_header, uint32_t current_index );
static uint32_t parse_TCP_header( uint8_t *p_data, TCP_HEADER *p_TCP_header, uint32_t current_index );
static uint32_t parse_DNS_header( uint8_t *p_data, DNS_HEADER *p_DNS_header, uint32_t current_index );
static uint32_t parse_rr_query_entry( uint8_t *p_data, RR_QUERY_ENTRY *p_rr_query_entry, uint32_t current_index, uint32_t *rr_index  );
static uint32_t parse_rr_entry( uint8_t *p_data, RR_ENTRY *p_rr_entry, uint32_t current_index, uint32_t *rr_index ,uint32_t type, char *p_text );

static uint8_t getBit( uint8_t value, uint8_t index ){
	return ( ( value >> index )  & 0x01) ;
}

void set_current_pcap_file( PCAP_FILE* p_pcap_file ){
	p_current_pcap_file = p_pcap_file;
	current_index = PCAP_FILE_GLOBAL_HEADER_SIZE;
	p_current_pcap_file_global_header = (PCAP_FILE_GLOBAL_HEADER*) p_pcap_file->p_data;

	print_info( "parser.c: set_current_pcap_file() --> STARTING...\n" );
	sprintf( text, "parser.c: set_current_pcap_file() --> get_size_pcap_entry_header() == %d\n", get_size_pcap_entry_header( p_current_pcap_file_global_header ) );
	print_debug( text );
	return;
}

PACKET* get_next_pcap_file_packet( void ){
	uint8_t *p_data = p_current_pcap_file->p_data;

	if ( p_current_pcap_file == NULL ){
		print_debug( "parser.c: get_next_pcap_file_packet() --> p_current_pcap_file == NULL\n" );
		return NULL;
	}

	PCAP_FILE_ENTRY_HEADER *p_pcap_file_entry_header = (PCAP_FILE_ENTRY_HEADER*) &p_data[current_index];
	if (  p_pcap_file_entry_header->incl_len != p_pcap_file_entry_header->orig_len ){
		print_debug( "parser.c: get_next_pcap_file_packet() --> incl_len != orig_len\n" );
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

void parse_packet( PACKET *p_packet ){
	uint32_t temp_index = 0;
	uint8_t *p_data = p_packet->p_data;

	temp_index = parse_ethernet_header( p_data, &(p_packet->ethernet_header), temp_index );

	if ( get_ethernet_type( p_packet ) == TYPE_IP4 ){
		temp_index = parse_IP4_header( p_data, &(p_packet->IP4_header), temp_index );

		if ( has_UDP_header( p_packet ) ){
			temp_index = parse_UDP_header( p_data, &(p_packet->UDP_header), temp_index );
		} else if ( has_TCP_header( p_packet ) ){
			temp_index = parse_TCP_header( p_data, &(p_packet->TCP_header), temp_index );
		} 

		if ( !has_DNS_header( p_packet) ){
			print_debug( "parser.c: get_next_pcap_file_packet() --> port_dst != 53 and port_src != 53\n" );
			return;
		}

		temp_index = parse_DNS_header( p_data, &(p_packet->DNS_header), temp_index );

		if ( get_DNS_number_of_queries( p_packet ) != 1 ){
			print_debug( "parser.c: get_next_pcap_file_packet() --> #queries != 1\n" );
			return;
		}

		uint32_t rr_index = 12;

		temp_index = parse_rr_query_entry( p_data, &(p_packet->rr_query_entry), temp_index, &rr_index );

		uint32_t rr_entry_index = 0;

		for ( int i = 0; i < get_DNS_number_of_answers( p_packet ); i++ ){

			p_packet->p_rr_entries[rr_entry_index] = init_rr_entry();
			temp_index = parse_rr_entry( p_data, p_packet->p_rr_entries[rr_entry_index], temp_index, &rr_index, TYPE_ANSWER, p_packet->rr_query_entry.name );
			rr_entry_index++;
		}

		for ( int i = 0; i < get_DNS_number_of_authorities( p_packet ); i++ ){
			p_packet->p_rr_entries[rr_entry_index] = init_rr_entry();
			temp_index = parse_rr_entry( p_data, p_packet->p_rr_entries[rr_entry_index], temp_index, &rr_index, TYPE_AUTHORITY, p_packet->rr_query_entry.name );
			rr_entry_index++;
		}

		for ( int i = 0; i < get_DNS_number_of_additionals( p_packet ); i++ ){
			p_packet->p_rr_entries[rr_entry_index] = init_rr_entry();
			temp_index = parse_rr_entry( p_data, p_packet->p_rr_entries[rr_entry_index], temp_index, &rr_index, TYPE_ADDITIONAL, p_packet->rr_query_entry.name );
			rr_entry_index++;
		}
	} else if ( get_ethernet_type( p_packet ) == TYPE_ARP ){
		temp_index = parse_ARP_header( p_data, &(p_packet->ARP_header), temp_index );
		return;
	} else{
		print_debug( "parser.c: get_next_pcap_file_packet() --> no IP4 or ARP, abort\n" );
		return;
	}
}


static uint32_t parse_ethernet_header( uint8_t *p_data, ETHERNET_HEADER *p_ethernet_header, uint32_t current_index ){
	memcpy( p_ethernet_header->MAC_dst, &p_data[  current_index + 0 ], 6 );
	memcpy( p_ethernet_header->MAC_src, &p_data[  current_index + 6 ], 6 );
	memcpy( &(p_ethernet_header->type), &p_data[  current_index + 12 ], 2 );
	swap_variable( (uint8_t *) &(p_ethernet_header->type), 2 );

	return current_index + get_ethernet_header_size();
}

static uint32_t parse_ARP_header( uint8_t *p_data, ARP_HEADER *p_ARP_header, uint32_t current_index ){
	memcpy( &(p_ARP_header->hardware_type), &p_data[  current_index + 0 ], 2 );
	swap_variable( (uint8_t *) &(p_ARP_header->hardware_type), 2 );

	memcpy( &(p_ARP_header->protocol_type), &p_data[  current_index + 2 ], 2 );
	swap_variable( (uint8_t *) &(p_ARP_header->protocol_type), 2 );

	memcpy( &(p_ARP_header->hardware_size), &p_data[  current_index + 4 ], 1 );
	memcpy( &(p_ARP_header->protocol_size), &p_data[  current_index + 5 ], 1 );

	if ( p_ARP_header->hardware_size != 6 ){
		print_info( "packet.c: parse_ARP_header() --> hardware_size != 6\n" );
		return -1;
	}

	if ( p_ARP_header->protocol_size != 4 ){
		print_info( "packet.c: protocol_size() --> protocol_size != 4\n" );
		return -1;
	}

	memcpy( &(p_ARP_header->opcode), &p_data[  current_index + 6 ], 2 );
	swap_variable( (uint8_t *) &(p_ARP_header->opcode), 2 );

	memcpy( p_ARP_header->MAC_src, &p_data[  current_index +  8 ], 6 );
	memcpy( p_ARP_header->IP4_src, &p_data[  current_index + 14 ], 4 );
	memcpy( p_ARP_header->MAC_dst, &p_data[  current_index + 18 ], 6 );
	memcpy( p_ARP_header->IP4_dst, &p_data[  current_index + 24 ], 4 );

	return current_index + get_ARP_header_size();
}

static uint32_t parse_IP4_header( uint8_t *p_data, IP4_HEADER *p_IP4_header, uint32_t current_index ){
	memcpy( &(p_IP4_header->IHL), &p_data[ current_index + 0 ], 1 );
	p_IP4_header->IHL &= 0x0F;

	memcpy( &(p_IP4_header->protocol), &p_data[ current_index +  9 ], 1 );
	memcpy( &(p_IP4_header->IP4_src), &p_data[ current_index + 12 ], 4 );
	memcpy( &(p_IP4_header->IP4_dst), &p_data[ current_index + 16 ], 4 );

	return current_index + get_IP4_header_size( p_IP4_header );
}

static uint32_t parse_UDP_header( uint8_t *p_data, UDP_HEADER *p_UDP_header, uint32_t current_index ){
	memcpy( &(p_UDP_header->port_dst), &p_data[ current_index +  0 ], 2 );
	swap_variable( (uint8_t *) &(p_UDP_header->port_dst), 2 );

	memcpy( &(p_UDP_header->port_src), &p_data[ current_index +  2 ], 2 );
	swap_variable( (uint8_t *) &(p_UDP_header->port_src), 2 );

	memcpy( &(p_UDP_header->length), &p_data[ current_index + 4 ], 2 );
	swap_variable( (uint8_t *) &(p_UDP_header->length), 2 );

	memcpy( &(p_UDP_header->checksum), &p_data[ current_index + 6 ], 2 );
	swap_variable( (uint8_t *) &(p_UDP_header->checksum), 2 );
	
	return current_index + get_UDP_header_size();
}


static uint32_t parse_TCP_header( uint8_t *p_data, TCP_HEADER *p_TCP_header, uint32_t current_index ){
	memcpy( &(p_TCP_header->port_src), &p_data[ current_index + 0 ], 2 );
	swap_variable( (uint8_t *) &(p_TCP_header->port_src), 2 );

	memcpy( &(p_TCP_header->port_dst), &p_data[ current_index + 2 ], 2 );
	swap_variable( (uint8_t *) &(p_TCP_header->port_dst), 2 );

	memcpy( &(p_TCP_header->data_offset), &p_data[ current_index + 12 ], 1 );
	p_TCP_header->data_offset >>= 4;

	return current_index + get_TCP_header_size( p_TCP_header );
}

static uint32_t parse_DNS_header( uint8_t *p_data, DNS_HEADER *p_DNS_header, uint32_t current_index ){
	memcpy( &(p_DNS_header->identification), &p_data[ current_index + 0 ], 2 );
	swap_variable( (uint8_t *) &(p_DNS_header->identification), 2 );

	memcpy( &(p_DNS_header->QR), &p_data[ current_index + 2 ], 1 );
	p_DNS_header->QR = getBit( p_DNS_header->QR, 0 );

	memcpy( &(p_DNS_header->opcode), &p_data[ current_index + 2 ], 1 );
	(p_DNS_header->opcode) <<= 1;
	(p_DNS_header->opcode) >>= 4;

	memcpy( &(p_DNS_header->AA), &p_data[ current_index + 2 ], 1 );
	p_DNS_header->AA = getBit( p_DNS_header->AA, 5 );

	memcpy( &(p_DNS_header->TC), &p_data[ current_index + 2 ], 1 );
	p_DNS_header->TC = getBit( p_DNS_header->TC, 6 );

	memcpy( &(p_DNS_header->RD), &p_data[ current_index + 2 ], 1 );
	p_DNS_header->RD = getBit( p_DNS_header->RD, 7 );

	memcpy( &(p_DNS_header->RA), &p_data[ current_index + 3 ], 1 );
	p_DNS_header->RA = getBit( p_DNS_header->RA, 0 );

	memcpy( &(p_DNS_header->Z), &p_data[ current_index + 3 ], 1 );
	p_DNS_header->Z = getBit( p_DNS_header->Z, 1 );

	memcpy( &(p_DNS_header->AD), &p_data[ current_index + 2 ], 1 );
	p_DNS_header->AD = getBit( p_DNS_header->AD, 2 );

	memcpy( &(p_DNS_header->CD), &p_data[ current_index + 3 ], 1 );
	p_DNS_header->CD = getBit( p_DNS_header->CD, 3 );

	memcpy( &(p_DNS_header->rcode), &p_data[ current_index + 3 ], 1 );
	(p_DNS_header->rcode) &= 0x0F;

	memcpy( &(p_DNS_header->query_count), &p_data[ current_index + 4 ], 2 );
	swap_variable( (uint8_t *) &(p_DNS_header->query_count), 2 );

	memcpy( &(p_DNS_header->answer_count), &p_data[ current_index + 6 ], 2 );
	swap_variable( (uint8_t *) &(p_DNS_header->answer_count), 2 );

	memcpy( &(p_DNS_header->authority_count), &p_data[ current_index + 8 ], 2 );
	swap_variable( (uint8_t *) &(p_DNS_header->authority_count), 2 );

	memcpy( &(p_DNS_header->additional_count), &p_data[ current_index + 10 ], 2 );
	swap_variable( (uint8_t *) &(p_DNS_header->additional_count), 2 );

	return current_index + get_DNS_header_size();
}

uint32_t parse_rr_query_entry( uint8_t *p_data, RR_QUERY_ENTRY *p_rr_query_entry, uint32_t current_index, uint32_t *p_rr_index ){
	uint32_t size = 0;

	for( int i = 0; i < 100; i++ ){
		p_rr_query_entry->name[i] = 0;
	}

	do{
		p_rr_query_entry->name[size] = p_data[ current_index + size ];
		size++;
	} while ( p_data[ current_index + size ] != 0 );

	p_rr_query_entry->name[size] = p_data[ current_index + size ];
	size++;

	set_domain_name( p_rr_query_entry->name, *p_rr_index , size );

	memcpy( &(p_rr_query_entry->rr_type), &p_data[ current_index + size ], 2 );
	swap_variable( (uint8_t *) &(p_rr_query_entry->rr_type), 2 );
	size += 2;

	memcpy( &(p_rr_query_entry->rr_class), &p_data[ current_index + size ], 2 );
	swap_variable( (uint8_t *) &(p_rr_query_entry->rr_class), 2 );
	size += 2;

	*p_rr_index += size;
	return current_index + size;
}

static uint32_t parse_rr_entry( uint8_t *p_data, RR_ENTRY *p_rr_entry, uint32_t current_index, uint32_t *p_rr_index , uint32_t type, char* p_name ){
	p_rr_entry->type = type;
	sprintf( p_rr_entry->name, "%s", p_name );

	memcpy( &(p_rr_entry->rr_type), &p_data[ current_index + 2 ], 2 );
	swap_variable( (uint8_t *) &(p_rr_entry->rr_type), 2 );

	memcpy( &(p_rr_entry->rr_class), &p_data[ current_index + 4 ], 2 );
	swap_variable( (uint8_t *) &(p_rr_entry->rr_class), 2 );

	memcpy( &(p_rr_entry->TTL), &p_data[ current_index + 6 ], 4 );
	swap_variable( (uint8_t *) &(p_rr_entry->TTL), 4 );

	memcpy( &(p_rr_entry->length), &p_data[ current_index + 10 ], 2 );
	swap_variable( (uint8_t *) &(p_rr_entry->length), 2 );

	p_rr_entry->p_rr_data = malloc( p_rr_entry->length );

	for ( int i = 0; i < p_rr_entry->length; i++ ){
		p_rr_entry->p_rr_data[i] = p_data[ current_index + 12 + i ];
	}

	uint32_t rr_type = get_rr_entry_rr_type( p_rr_entry );

	if ( rr_type == TYPE_RR_NS || rr_type == TYPE_RR_CNAME || rr_type == TYPE_RR_PTR || rr_type == TYPE_RR_TXT ){
		memcpy( p_rr_entry->name, &p_data[ current_index + 12 ], p_rr_entry->length );
		set_domain_name( p_rr_entry->name, *p_rr_index + 12, p_rr_entry->length );
	}

	if ( rr_type == TYPE_RR_MX ){
		memcpy( p_rr_entry->name, &p_data[ current_index + 14 ], p_rr_entry->length - 2 );
		set_domain_name( p_rr_entry->name, *p_rr_index + 14, p_rr_entry->length - 2 );
	}

	*p_rr_index += get_rr_entry_size( p_rr_entry );
	return current_index + get_rr_entry_size( p_rr_entry );
}
