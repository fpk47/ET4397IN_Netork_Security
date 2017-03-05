#include "packet.h"
#include "message.h"
#include "tools.h"

static void print_rr_entry( RR_ENTRY *p_rr_entry, uint32_t rr_entry_index );
static void print_rr_entry_a( uint8_t *p_data );
static void print_rr_entry_ns( uint8_t *p_data, uint32_t length );
static void print_rr_entry_cname( uint8_t *p_data, uint32_t length );
static void print_rr_entry_soa( uint8_t *p_data, uint32_t length  );
static void print_rr_entry_ptr( uint8_t *p_data, uint32_t length );
static void print_rr_entry_mx( uint8_t *p_data, uint32_t length );
static void print_rr_entry_txt( uint8_t *p_data, uint32_t length );

uint32_t get_ethernet_header_size(){ return 14; }
uint32_t get_ip_4_header_size( IP_4_HEADER *p_ip_4_header ){ return ( p_ip_4_header->IHL ) * 4; }
uint32_t get_udp_header_size(){ return 8; }
uint32_t get_tcp_header_size( TCP_HEADER *p_tcp_header ){ return ( p_tcp_header->data_offset ) * 4; }
uint32_t get_dns_header_size(){ return 12; }
uint32_t get_rr_entry_size( RR_ENTRY *p_rr_entry ){ return p_rr_entry->length + 12; }

uint16_t get_ethernet_type( PACKET* p_packet ){ return p_packet->ethernet_header.type; }
uint32_t get_dns_number_of_queries( PACKET* p_packet ){ return p_packet->dns_header.query_count; }
uint32_t get_dns_number_of_answers( PACKET* p_packet ){ return p_packet->dns_header.answer_count; }
uint32_t get_dns_number_of_authorities( PACKET* p_packet ){ return p_packet->dns_header.authority_count; }
uint32_t get_dns_number_of_additionals( PACKET* p_packet ){ return p_packet->dns_header.additional_count; }

uint32_t get_rr_entry_rr_type( RR_ENTRY *p_rr_entry ){ return p_rr_entry->rr_type; }

char* get_rr_entry_type_name( RR_ENTRY *p_rr_entry ){
	static char temp_text[100];

	if ( p_rr_entry->type == TYPE_ANSWER     ){ sprintf( temp_text, "ANSWER"     ); return temp_text; }
	if ( p_rr_entry->type == TYPE_AUTHORITY  ){ sprintf( temp_text, "AUTHORITY"  ); return temp_text; }
	if ( p_rr_entry->type == TYPE_ADDITIONAL ){ sprintf( temp_text, "ADDITIONAL" ); return temp_text; }
	
	return NULL;
}

#define CLASS_RR_IN 1
#define CLASS_RR_CS 2
#define CLASS_RR_CH 3
#define CLASS_RR_HS 4

char* get_rr_entry_rr_class_name( RR_ENTRY *p_rr_entry ){
	static char temp_text[100];

	if ( p_rr_entry->rr_class == CLASS_RR_IN ){ sprintf( temp_text, "IN" ); return temp_text; }
	if ( p_rr_entry->rr_class == CLASS_RR_CS ){ sprintf( temp_text, "CS" ); return temp_text; }
	if ( p_rr_entry->rr_class == CLASS_RR_CH ){ sprintf( temp_text, "CH" ); return temp_text; }
	if ( p_rr_entry->rr_class == CLASS_RR_HS ){ sprintf( temp_text, "HS" ); return temp_text; }

	return NULL;
}

char* get_rr_entry_rr_type_name( RR_ENTRY *p_rr_entry ){
	static char temp_text[100];

	if ( p_rr_entry->rr_type == TYPE_RR_AAAA   ){ sprintf( temp_text, "AAAA"  ); return temp_text; }
	if ( p_rr_entry->rr_type == TYPE_RR_A_STAR ){ sprintf( temp_text, "*A"    ); return temp_text; }
	if ( p_rr_entry->rr_type == TYPE_RR_A      ){ sprintf( temp_text, "A"     ); return temp_text; }
	if ( p_rr_entry->rr_type == TYPE_RR_NS     ){ sprintf( temp_text, "NS"    ); return temp_text; }
	if ( p_rr_entry->rr_type == TYPE_RR_CNAME  ){ sprintf( temp_text, "CNAME" ); return temp_text; }
	if ( p_rr_entry->rr_type == TYPE_RR_SOA    ){ sprintf( temp_text, "SOA"   ); return temp_text; }
	if ( p_rr_entry->rr_type == TYPE_RR_PTR    ){ sprintf( temp_text, "PTR"   ); return temp_text; }
	if ( p_rr_entry->rr_type == TYPE_RR_MX     ){ sprintf( temp_text, "MX"    ); return temp_text; }
	if ( p_rr_entry->rr_type == TYPE_RR_TXT    ){ sprintf( temp_text, "TXT"   ); return temp_text; }

	return NULL;
}

char* get_rr_query_entry_rr_class_name( RR_QUERY_ENTRY *p_rr_query_entry ){
	static char temp_text[100];

	if ( p_rr_query_entry->rr_class == CLASS_RR_IN ){ sprintf( temp_text, "IN" ); return temp_text; }
	if ( p_rr_query_entry->rr_class == CLASS_RR_CS ){ sprintf( temp_text, "CS" ); return temp_text; }
	if ( p_rr_query_entry->rr_class == CLASS_RR_CH ){ sprintf( temp_text, "CH" ); return temp_text; }
	if ( p_rr_query_entry->rr_class == CLASS_RR_HS ){ sprintf( temp_text, "HS" ); return temp_text; }

	return NULL;
}

char* get_rr_query_entry_rr_type_name( RR_QUERY_ENTRY *p_rr_query_entry ){
	static char temp_text[100];

	if ( p_rr_query_entry->rr_type == TYPE_RR_AAAA   ){ sprintf( temp_text, "AAAA"  ); return temp_text; }
	if ( p_rr_query_entry->rr_type == TYPE_RR_A_STAR ){ sprintf( temp_text, "*A"    ); return temp_text; }
	if ( p_rr_query_entry->rr_type == TYPE_RR_A      ){ sprintf( temp_text, "A"     ); return temp_text; }
	if ( p_rr_query_entry->rr_type == TYPE_RR_NS     ){ sprintf( temp_text, "NS"    ); return temp_text; }
	if ( p_rr_query_entry->rr_type == TYPE_RR_CNAME  ){ sprintf( temp_text, "CNAME" ); return temp_text; }
	if ( p_rr_query_entry->rr_type == TYPE_RR_SOA    ){ sprintf( temp_text, "SOA"   ); return temp_text; }
	if ( p_rr_query_entry->rr_type == TYPE_RR_PTR    ){ sprintf( temp_text, "PTR"   ); return temp_text; }
	if ( p_rr_query_entry->rr_type == TYPE_RR_MX     ){ sprintf( temp_text, "MX"    ); return temp_text; }
	if ( p_rr_query_entry->rr_type == TYPE_RR_TXT    ){ sprintf( temp_text, "TXT"   ); return temp_text; }

	return NULL;
}

ETHERNET_HEADER* get_ethernet_header( PACKET *p_packet ){ return (ETHERNET_HEADER*) &(p_packet->ethernet_header); }
IP_4_HEADER* get_IP_4_header( PACKET *p_packet ){ return (IP_4_HEADER*) &(p_packet->ip_4_header); }
UDP_HEADER* get_UDP_header( PACKET *p_packet ){ return (UDP_HEADER*) &(p_packet->udp_header); }
TCP_HEADER* get_TCP_header( PACKET *p_packet ){ return (TCP_HEADER*) &(p_packet->tcp_header); }
DNS_HEADER* get_DNS_header( PACKET *p_packet ){ return (DNS_HEADER*) &(p_packet->dns_header); }
RR_QUERY_ENTRY* get_rr_query_entry( PACKET *p_packet ){ return  (RR_QUERY_ENTRY*) &(p_packet->rr_query_entry); }

uint8_t is_udp_packet( PACKET *p_packet ){
	if ( p_packet == NULL ){
		return FALSE;
	}

	if ( p_packet->ip_4_header.protocol == TYPE_UDP ){
		return TRUE;
	} else{
		return FALSE;
	}
}

uint8_t is_tcp_packet( PACKET *p_packet ){
	if ( p_packet == NULL ){
		return FALSE;
	}

	if ( p_packet->ip_4_header.protocol == TYPE_TCP ){
		return TRUE;
	} else{
		return FALSE;
	}
}

uint8_t is_dns_packet( PACKET *p_packet ){
	if ( p_packet == NULL ){
		return FALSE;
	}

	if ( is_udp_packet( p_packet ) ){
		if ( p_packet->udp_header.port_dst == 53 || p_packet->udp_header.port_src == 53 ) return TRUE;
	} else if ( is_tcp_packet( p_packet ) ){
		if ( p_packet->tcp_header.port_dst == 53 || p_packet->tcp_header.port_src == 53 ) return TRUE;
	} 
	
	return FALSE;
}

RR_ENTRY* init_rr_entry( void ){
	RR_ENTRY* p_rr_entry = (RR_ENTRY*) malloc( sizeof( RR_ENTRY ) );
	p_rr_entry->p_rr_data = NULL;
	return p_rr_entry ;
}

PACKET* init_packet_u_char( uint32_t size, const u_char *data ){
	PACKET* p_packet = (PACKET*) malloc( sizeof( PACKET ) );
	p_packet->p_data = (u_char*) malloc( size );
	p_packet->size = size;

	for( int i = 0; i < size; i++ ){
		p_packet->p_data[i] = data[i];
	}

	for( int i = 0; i < NUMBER_OF_RR_ENTRIES; i++ ){
		p_packet->p_rr_entries[i] = NULL;
	}

	return p_packet;
}

PACKET* init_packet_uint8_t( uint32_t size, uint8_t *data ){
	PACKET* p_packet = (PACKET*) malloc( sizeof( PACKET ) );
	p_packet->p_data = (uint8_t*) malloc( size );
	p_packet->size = size;

	for( int i = 0; i < size; i++ ){
		p_packet->p_data[i] = data[i];
	}

	return p_packet;
}

void free_packet( PACKET* p_packet ){
	if ( p_packet == NULL ){
		return;
	}

	if ( is_dns_packet( p_packet ) ){
		for ( int i = 0; i < NUMBER_OF_RR_ENTRIES; i++ ){
			//free_rr_entry( p_packet->p_rr_entries[i] ); // NEED TO FIX..
		}
	}

	free( p_packet->p_data );
	free( p_packet );
}

void free_rr_entry( RR_ENTRY *p_rr_entry ){
	if ( p_rr_entry != NULL ){
		if ( p_rr_entry->p_rr_data != NULL ){
			free( p_rr_entry->p_rr_data );
		}

		free( p_rr_entry );
	}
}

void print_packet( PACKET* p_packet ){
    if ( p_packet == NULL ) {
        print_debug( "packet.c: print_packet() --> p_packet == NULL\n" );
        return;
    }

    if ( p_packet->size == 0 ) {
        print_debug( "packet.c: print_packet() --> p_packet->size == 0\n" );
        return;
    }

	uint32_t size = p_packet->size;
	uint8_t *p_data = p_packet->p_data;

	ETHERNET_HEADER *p_ethernet_header = &(p_packet->ethernet_header);
	uint8_t *p_mac_dst = p_ethernet_header->mac_dst;
	uint8_t *p_mac_src = p_ethernet_header->mac_src;

    printf("----PACKET (total size = %d)----\n", size );
    printf("   ETHERNET: mac_dst     --> %s\n", get_mac_address( p_mac_dst ) );
    printf("   ETHERNET: mac_src     --> %s\n", get_mac_address( p_mac_src ) );
	printf("   ETHERNET: size        --> %d\n", get_ethernet_header_size() ); 

    if ( get_ethernet_type( p_packet ) == TYPE_IP4 ) { printf("   ETHERNET: type        --> IP4\n" ); }
    else									   				  { printf("   ETHERNET: type        --> %04x [NOT IP4, ABORTING]\n", p_ethernet_header->type ); printf("-----------------\n" ); return; }

	IP_4_HEADER *p_ip_4_header = &(p_packet->ip_4_header);
	uint8_t *p_ip_4_dst = p_ip_4_header->ip_4_dst;
	uint8_t *p_ip_4_src = p_ip_4_header->ip_4_src;

    printf("        IP4: ip4_dst     --> %s\n", get_ip_4_address( p_ip_4_dst ) );
    printf("        IP4: ip4_src     --> %s\n", get_ip_4_address( p_ip_4_src ) );
    printf("        IP4: size        --> %d [IHL = %d]\n", get_ip_4_header_size( p_ip_4_header ), p_ip_4_header->IHL ); 

         if ( is_udp_packet( p_packet ) ) { printf("        IP4: protocol    --> UDP\n" ); }
    else if ( is_tcp_packet( p_packet ) ) { printf("        IP4: protocol    --> TCP\n" ); }
    else									        { printf("        IP4: protocol    --> %02x [NOT UDP/TCP, ABORTING]\n", p_ip_4_header->protocol ); printf("-----------------\n" ); return; }

    if ( is_udp_packet( p_packet ) ){
    	UDP_HEADER *p_udp_header = &(p_packet->udp_header);

    	printf("        UDP: port_dst    --> %d\n", p_udp_header->port_dst ); 
    	printf("        UDP: port_src    --> %d\n", p_udp_header->port_src ); 
    	printf("        UDP: size        --> %d\n", get_udp_header_size() ); 
    } else if ( is_tcp_packet( p_packet ) ){
    	TCP_HEADER *p_tcp_header = &(p_packet->tcp_header);

    	printf("        TCP: port_dst    --> %d\n", p_tcp_header->port_dst ); 
    	printf("        TCP: port_src.   --> %d\n", p_tcp_header->port_src ); 
    	printf("        TCP: size        --> %d [data_offset = %d]\n", get_tcp_header_size( p_tcp_header ), p_tcp_header->data_offset ); 
    }

    if ( is_dns_packet( p_packet) ){
    	DNS_HEADER *p_dns_header = &(p_packet->dns_header);
    	if ( PRINT_MODE_FULL ){
	    	printf("        DNS: id          --> %d\n", p_dns_header->identification ); 
	    	printf("        DNS: QR          --> %d\n", p_dns_header->QR ); 
	    	printf("        DNS: opcode      --> %d\n", p_dns_header->opcode ); 
	    	printf("        DNS: AA          --> %d\n", p_dns_header->AA ); 
	    	printf("        DNS: TC          --> %d\n", p_dns_header->TC ); 
	    	printf("        DNS: RD          --> %d\n", p_dns_header->RD ); 
	    	printf("        DNS: RA          --> %d\n", p_dns_header->RA ); 
	    	printf("        DNS: Z           --> %d\n", p_dns_header->Z ); 
	    	printf("        DNS: AD          --> %d\n", p_dns_header->AD ); 
	    	printf("        DNS: CD          --> %d\n", p_dns_header->CD ); 
	    	printf("        DNS: rcode       --> %d\n", p_dns_header->rcode ); 
    	}

    	printf("        DNS: #query      --> %d\n", p_dns_header->query_count ); 
    	printf("        DNS: #answer     --> %d\n", p_dns_header->answer_count ); 
    	printf("        DNS: #authority  --> %d\n", p_dns_header->authority_count ); 
    	printf("        DNS: #additional --> %d\n", p_dns_header->additional_count ); 
    } else{
    	printf("        DNS: [NOT PORT 53, ABORTING], \n" ); 
    	printf("-----------------\n" ); 
    	return;
    }

    RR_QUERY_ENTRY *p_rr_query_entry = get_rr_query_entry( p_packet );

    if ( get_dns_number_of_queries( p_packet ) == 1 ){
    	printf("        DNS: {QUERY} TYPE %s, CLASS %s, %s\n", get_rr_query_entry_rr_type_name( p_rr_query_entry ), get_rr_query_entry_rr_class_name( p_rr_query_entry ), get_domain_name( p_rr_query_entry->name, 999 ) ); 
    } else if ( get_dns_number_of_queries( p_packet ) == 1  && get_rr_query_entry_rr_type_name( p_rr_query_entry ) == NULL ){
		printf("        DNS: {QUERY} TYPE %d, CLASS %s, %s\n", p_rr_query_entry->rr_type, get_rr_query_entry_rr_class_name( p_rr_query_entry ), get_domain_name( p_rr_query_entry->name, 999 ) ); 
    } else{
    	printf("        DNS: [#query != 1, ABORTING]\n" );
    	printf("-----------------\n" ); 
    	return;
    }

    uint32_t rr_entry_index = 0;

    for ( int i = 0; i < get_dns_number_of_answers( p_packet ); i++ ){
		print_rr_entry( p_packet->p_rr_entries[rr_entry_index], rr_entry_index );
		rr_entry_index++;
	}

	for ( int i = 0; i < get_dns_number_of_authorities( p_packet ); i++ ){
		print_rr_entry( p_packet->p_rr_entries[rr_entry_index], rr_entry_index );	
		rr_entry_index++;
	}

	for ( int i = 0; i < get_dns_number_of_additionals( p_packet ); i++ ){
		print_rr_entry( p_packet->p_rr_entries[rr_entry_index], rr_entry_index );
		rr_entry_index++;
	}

    printf("-----------------\n" );
}

static void print_rr_entry( RR_ENTRY *p_rr_entry, uint32_t rr_entry_index ){
	char *p_rr_class_name = get_rr_entry_rr_type_name( p_rr_entry );

	if ( p_rr_class_name != NULL ){
		printf( "        DNS: {%s}", get_rr_entry_type_name( p_rr_entry ) ); 
		printf( " TYPE %s", get_rr_entry_rr_type_name( p_rr_entry ) );
		printf( ", CLASS %s", get_rr_entry_rr_class_name( p_rr_entry ) );
		printf( ", TTL=%d", p_rr_entry->TTL );
		printf( ", length=%d\n", p_rr_entry->length );

			 if ( get_rr_entry_rr_type( p_rr_entry ) == TYPE_RR_A     ){ print_rr_entry_a( p_rr_entry->p_rr_data ); }
		else if ( get_rr_entry_rr_type( p_rr_entry ) == TYPE_RR_NS    ){ print_rr_entry_ns( p_rr_entry->p_rr_data, p_rr_entry->length ); }
		else if ( get_rr_entry_rr_type( p_rr_entry ) == TYPE_RR_CNAME ){ print_rr_entry_cname( p_rr_entry->p_rr_data, p_rr_entry->length); }
		else if ( get_rr_entry_rr_type( p_rr_entry ) == TYPE_RR_SOA   ){ print_rr_entry_soa( p_rr_entry->p_rr_data, p_rr_entry->length ); }
		else if ( get_rr_entry_rr_type( p_rr_entry ) == TYPE_RR_PTR   ){ print_rr_entry_ptr( p_rr_entry->p_rr_data, p_rr_entry->length ); }
		else if ( get_rr_entry_rr_type( p_rr_entry ) == TYPE_RR_MX    ){ print_rr_entry_mx( p_rr_entry->p_rr_data, p_rr_entry->length ); }
		else if ( get_rr_entry_rr_type( p_rr_entry ) == TYPE_RR_TXT   ){ print_rr_entry_txt( p_rr_entry->p_rr_data, p_rr_entry->length ); }

	} else{
		printf("        DNS: {%s} [UKNOWN RR_TYPE 0x%04x] length = %d  \n", get_rr_entry_type_name( p_rr_entry ), get_rr_entry_rr_type( p_rr_entry ), p_rr_entry->length ); 
	}
}

static void print_rr_entry_a( uint8_t *p_data ){
	printf("           : %s\n", get_ip_4_address( p_data ) );
}

static void print_rr_entry_ns( uint8_t *p_data, uint32_t length ){
	printf("           : %s\n", get_domain_name( (char*) p_data, length) );
}

static void print_rr_entry_cname( uint8_t *p_data, uint32_t length ){
	printf("           : %s\n", get_domain_name( (char*) p_data, length ) );
}

static void print_rr_entry_soa( uint8_t *p_data, uint32_t length ){
	//int index = 0;

	printf("           : mname = TODO\n"/*, get_domain_name( (char*) p_data, 999 ) */);
/*
	do{
		index++;
	} while ( p_data[index] != 0 );
*/
	printf("           : rname = TODO\n"/*, get_domain_name( (char*) p_data, 999 )*/ );
/*
	do{
		index++;
	} while ( p_data[index] != 0 );*/

	printf("           : serial = 0x%08x\n", get_uint32_t( &p_data[ length - 16 ] ) ); 
	printf("           : refresh = 0x%08x\n", get_uint32_t( &p_data[ length - 12 ]  ) ); 
	printf("           : retry = 0x%08x\n", get_uint32_t( &p_data[ length - 8 ]  ) ); 
	printf("           : expire = 0x%08x\n", get_uint32_t( &p_data[ length - 4 ]  ) ); 
}

static void print_rr_entry_ptr( uint8_t *p_data, uint32_t length ){
	printf("           : ptr = %s\n", get_domain_name( (char*) p_data, length ) );
}

static void print_rr_entry_mx( uint8_t *p_data, uint32_t length ){
	printf("           : preferences = %d\n", get_uint32_t( p_data ) ); 
	printf("           : exhange = %s\n", get_domain_name( (char*) &p_data[2], length ) );
}

static void print_rr_entry_txt( uint8_t *p_data, uint32_t length ){
	printf("           : txt = %s\n", get_domain_name( (char*) p_data, length ) );
}







