#include "packet.h"
#include "message.h"
#include "tools.h"

static int counter = 0;

static void print_ethernet_header( PACKET *p_packet );
static void print_arp_header( PACKET *p_packet );
static void print_ip4_header( PACKET *p_packet );
static void print_udp_header( PACKET *p_packet );
static void print_tcp_header( PACKET *p_packet );
static void print_dns_header( PACKET *p_packet );

static void print_rr_entry( RR_ENTRY *p_rr_entry, uint32_t rr_entry_index );
static void print_rr_entry_a( uint8_t *p_data );
static void print_rr_entry_ns( uint8_t *p_data, uint32_t length );
static void print_rr_entry_cname( uint8_t *p_data, uint32_t length );
static void print_rr_entry_soa( uint8_t *p_data, uint32_t length  );
static void print_rr_entry_ptr( uint8_t *p_data, uint32_t length );
static void print_rr_entry_mx( uint8_t *p_data, uint32_t length );
static void print_rr_entry_txt( uint8_t *p_data, uint32_t length );

uint32_t get_ethernet_header_size( void ){ return 14; }

uint32_t get_IP4_header_size( IP4_HEADER *p_ip4_header ){
	if ( p_ip4_header == NULL ){
		print_warning( "packet.c: get_IP4_header_size() --> p_ip4_header == NULL\n" );
		return -1;
	}

	return ( p_ip4_header->IHL ) * 4; 
}

uint32_t get_arp_header_size( void ){ return 28; }
uint32_t get_udp_header_size(){ return 8; }
uint32_t get_tcp_header_size( TCP_HEADER *p_tcp_header ){ return ( p_tcp_header->data_offset ) * 4; }
uint32_t get_dns_header_size( void ){ return 12; }
uint32_t get_rr_entry_size( RR_ENTRY *p_rr_entry ){ return p_rr_entry->length + 12; }

char* get_ethernet_type_name( PACKET* p_packet ){ 
	static char text[100];

	if ( is_arp_packet( p_packet ) ){
		sprintf( text, "ARP" );
	} else if ( is_ip4_packet( p_packet ) ){
		sprintf( text, "IP4" );
	} else if ( is_ip6_packet( p_packet ) ){
		sprintf( text, "IP6" );
	} else{
		sprintf( text, "%02x", get_ip4_protocol( p_packet ) );
	}
	
	return text;
}

uint16_t get_ethernet_type( PACKET* p_packet ){
	if ( p_packet == NULL ){
		print_warning( "packet.c: get_ethernet_type() --> p_packet == NULL\n" );
		return -1;
	}

 	return p_packet->ethernet_header.type; 
}

char* get_IP4_protocol_name( PACKET* p_packet ){
	static char text[100];

	if ( is_udp_packet( p_packet ) ){
		sprintf( text, "UDP" );
	} else if ( is_tcp_packet( p_packet ) ){
		sprintf( text, "IP4" );
	} else{
		sprintf( text, "%x", get_ip4_protocol( p_packet ) );
	}
	
	return text;
}

uint8_t get_ip4_protocol( PACKET* p_packet ){
	if ( p_packet == NULL ){
		print_warning( "packet.c: get_ip4_protocol() --> p_packet == NULL\n" );
		return -1;
	}

 	return p_packet->IP4_header.protocol; 
}

uint8_t get_ip4_IHL( PACKET *p_packet ){
		if ( p_packet == NULL ){
		print_warning( "packet.c: get_ip4_protocol() --> p_packet == NULL\n" );
		return -1;
	}

	return p_packet->IP4_header.IHL;
}

uint32_t get_dns_number_of_queries( PACKET* p_packet ){ 
	if ( p_packet == NULL ){
		print_warning( "packet.c: get_dns_number_of_queries() --> p_packet == NULL\n" );
		return -1;
	}

	return p_packet->dns_header.query_count; 
}

uint32_t get_dns_number_of_answers( PACKET* p_packet ){ 
	if ( p_packet == NULL ){
		print_warning( "packet.c: get_dns_number_of_answers() --> p_packet == NULL\n" );
		return -1;
	}

	return p_packet->dns_header.answer_count; 
}

uint32_t get_dns_number_of_authorities( PACKET* p_packet ){
	if ( p_packet == NULL ){
		print_warning( "packet.c: get_dns_number_of_authorities() --> p_packet == NULL\n" );
		return -1;
	}

	 return p_packet->dns_header.authority_count; 
}

uint32_t get_dns_number_of_additionals( PACKET* p_packet ){
	if ( p_packet == NULL ){
		print_warning( "packet.c: get_dns_number_of_additionals() --> p_packet == NULL\n" );
		return -1;
	}

	 return p_packet->dns_header.additional_count; 
}

uint32_t get_rr_entry_rr_type( RR_ENTRY *p_rr_entry ){ return p_rr_entry->rr_type; }

char* get_rr_entry_type_name( RR_ENTRY *p_rr_entry ){
	if ( p_rr_entry == NULL ){
		print_warning( "packet.c: get_rr_entry_type_name() --> p_rr_entry == NULL\n" );
		return NULL;
	}

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
	if ( p_rr_entry == NULL ){
		print_warning( "packet.c: get_rr_entry_rr_class_name() --> p_rr_entry == NULL\n" );
		return NULL;
	}

	static char temp_text[100];

	if ( p_rr_entry->rr_class == CLASS_RR_IN ){ sprintf( temp_text, "IN" ); return temp_text; }
	if ( p_rr_entry->rr_class == CLASS_RR_CS ){ sprintf( temp_text, "CS" ); return temp_text; }
	if ( p_rr_entry->rr_class == CLASS_RR_CH ){ sprintf( temp_text, "CH" ); return temp_text; }
	if ( p_rr_entry->rr_class == CLASS_RR_HS ){ sprintf( temp_text, "HS" ); return temp_text; }

	return NULL;
}

char* get_rr_entry_rr_type_name( RR_ENTRY *p_rr_entry ){
	if ( p_rr_entry == NULL ){
		print_warning( "packet.c: get_rr_entry_rr_type_name() --> p_rr_entry == NULL\n" );
		return NULL;
	}

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
	if ( p_rr_query_entry == NULL ){
		print_warning( "packet.c: get_rr_query_entry_rr_class_name() --> p_rr_query_entry == NULL\n" );
		return NULL;
	}
	
	static char temp_text[100];

	if ( p_rr_query_entry->rr_class == CLASS_RR_IN ){ sprintf( temp_text, "IN" ); return temp_text; }
	if ( p_rr_query_entry->rr_class == CLASS_RR_CS ){ sprintf( temp_text, "CS" ); return temp_text; }
	if ( p_rr_query_entry->rr_class == CLASS_RR_CH ){ sprintf( temp_text, "CH" ); return temp_text; }
	if ( p_rr_query_entry->rr_class == CLASS_RR_HS ){ sprintf( temp_text, "HS" ); return temp_text; }

	return NULL;
}

char* get_rr_query_entry_rr_type_name( RR_QUERY_ENTRY *p_rr_query_entry ){
	if ( p_rr_query_entry == NULL ){
		print_warning( "packet.c: get_rr_query_entry_rr_type_name() --> p_rr_query_entry == NULL\n" );
		return NULL;
	}
	
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
ARP_HEADER *get_arp_header( PACKET *p_packet ){ return (ARP_HEADER*) &(p_packet->arp_header); }
IP4_HEADER* get_IP4_header( PACKET *p_packet ){ return (IP4_HEADER*) &(p_packet->IP4_header); }
UDP_HEADER* get_UDP_header( PACKET *p_packet ){ return (UDP_HEADER*) &(p_packet->udp_header); }
TCP_HEADER* get_TCP_header( PACKET *p_packet ){ return (TCP_HEADER*) &(p_packet->tcp_header); }
DNS_HEADER* get_DNS_header( PACKET *p_packet ){ return (DNS_HEADER*) &(p_packet->dns_header); }
RR_QUERY_ENTRY* get_rr_query_entry( PACKET *p_packet ){ return  (RR_QUERY_ENTRY*) &(p_packet->rr_query_entry); }

uint8_t* get_IP4_src( PACKET *p_packet ){
	if ( p_packet == NULL ){
		print_warning( "packet.c: get_IP4_MAC_src() --> p_packet == NULL\n" );
		return NULL;
	}

	IP4_HEADER *p_IP4_header = get_IP4_header( p_packet );
	return p_IP4_header->IP4_src;
}

uint8_t* get_IP4_dst( PACKET *p_packet ){
	if ( p_packet == NULL ){
		print_warning( "packet.c: get_IP4_MAC_dst() --> p_packet == NULL\n" );
		return NULL;
	}

	IP4_HEADER *p_IP4_header = get_IP4_header( p_packet );
	return p_IP4_header->IP4_dst;
}

uint8_t* get_ethernet_MAC_src( PACKET *p_packet ){
	if ( p_packet == NULL ){
		print_warning( "packet.c: get_ethernet_MAC_src() --> p_packet == NULL\n" );
		return NULL;
	}

	ETHERNET_HEADER *p_ethernet_header = get_ethernet_header( p_packet );
	return p_ethernet_header->MAC_src;
}

uint8_t* get_ethernet_MAC_dst( PACKET *p_packet ){
	if ( p_packet == NULL ){
		print_warning( "packet.c: get_ethernet_MAC_dst() --> p_packet == NULL\n" );
		return NULL;
	}

	ETHERNET_HEADER *p_ethernet_header = get_ethernet_header( p_packet );
	return p_ethernet_header->MAC_dst;
}

uint8_t is_ip4_packet( PACKET *p_packet ){
	if ( p_packet == NULL ){
		print_warning( "packet.c: is_arp_packet() --> p_packet == NULL\n" );
		return FALSE;
	}

	if ( get_ethernet_type( p_packet ) == TYPE_IP4 ){
		return TRUE;
	} else{
		return FALSE;
	}
}

uint8_t is_ip6_packet( PACKET *p_packet ){
	if ( p_packet == NULL ){
		print_warning( "packet.c: is_arp_packet() --> p_packet == NULL\n" );
		return FALSE;
	}

	if ( get_ethernet_type( p_packet ) == TYPE_IP6 ){
		return TRUE;
	} else{
		return FALSE;
	}
}

uint8_t is_arp_packet( PACKET *p_packet ){
	if ( p_packet == NULL ){
		print_warning( "packet.c: is_arp_packet() --> p_packet == NULL\n" );
		return FALSE;
	}

	if ( get_ethernet_type( p_packet ) == TYPE_ARP ){
		ARP_HEADER *p_arp_header = get_arp_header( p_packet );

		if ( p_arp_header->hardware_size != 6 ){
			print_debug( "packet.c: is_arp_packet() --> hardware_size != 6\n" );
			return FALSE;
		}

		if ( p_arp_header->protocol_size != 4 ){
			print_debug( "packet.c: is_arp_packet() --> protocol_size != 4\n" );
			return FALSE;
		}

		return TRUE;
	} else{
		return FALSE;
	}
}

uint8_t is_udp_packet( PACKET *p_packet ){
	if ( p_packet == NULL ){
		print_warning( "packet.c: is_udp_packet() --> p_packet == NULL\n" );
		return FALSE;
	}

	if ( !is_ip4_packet( p_packet ) ){
		return FALSE;
	}

	if ( p_packet->IP4_header.protocol == TYPE_UDP ){
		return TRUE;
	} else{
		return FALSE;
	}
}

uint8_t is_tcp_packet( PACKET *p_packet ){
	if ( p_packet == NULL ){
		print_warning( "packet.c: is_tcp_packet() --> p_packet == NULL\n" );
		return FALSE;
	}

	if ( !is_ip4_packet( p_packet ) ){
		return FALSE;
	}

	if ( p_packet->IP4_header.protocol == TYPE_TCP ){
		return TRUE;
	} else{
		return FALSE;
	}
}

uint8_t is_dns_packet( PACKET *p_packet ){
	if ( p_packet == NULL ){
		print_warning( "packet.c: is_dns_packet() --> p_packet == NULL\n" );
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

PACKET* init_packet_u_char( uint32_t size, const u_char *p_data ){
	if ( p_data == NULL ){
		print_warning( "packet.c: init_packet_u_char() --> p_data == NULL\n" );
		return FALSE;
	}

	PACKET* p_packet = (PACKET*) malloc( sizeof( PACKET ) );
	p_packet->p_data = (u_char*) malloc( size );
	p_packet->size = size;

	for( int i = 0; i < size; i++ ){
		p_packet->p_data[i] = p_data[i];
	}

	for( int i = 0; i < NUMBER_OF_RR_ENTRIES; i++ ){
		p_packet->p_rr_entries[i] = NULL;
	}

	return p_packet;
}

PACKET* init_packet_uint8_t( uint32_t size, uint8_t *p_data ){
	if ( p_data == NULL ){
		print_warning( "packet.c: init_packet_uint8_t() --> p_data == NULL\n" );
		return FALSE;
	}

	PACKET* p_packet = (PACKET*) malloc( sizeof( PACKET ) );
	p_packet->p_data = (uint8_t*) malloc( size );
	p_packet->size = size;

	for( int i = 0; i < size; i++ ){
		p_packet->p_data[i] = p_data[i];
	}

	return p_packet;
}

void free_packet( PACKET* p_packet ){
	if ( p_packet == NULL ){
		print_warning( "packet.c: free_packet() --> p_packet == NULL\n" );
		return;
	}

	if ( is_dns_packet( p_packet ) ){
		for ( int i = 0; i < NUMBER_OF_RR_ENTRIES; i++ ){
			if ( p_packet->p_rr_entries[i] != NULL ){
				free_rr_entry( p_packet->p_rr_entries[i] );
			}
		}
	}

	free( p_packet->p_data );
	free( p_packet );
}

PACKET* clone_packet( PACKET* p_packet ){
	if ( p_packet == NULL ){
		print_warning( "packet.c: clone_packet() --> p_packet == NULL\n" );
		return NULL;
	}

	return init_packet_uint8_t( p_packet->size, p_packet->p_data );
}

void free_rr_entry( RR_ENTRY *p_rr_entry ){
	if ( p_rr_entry == NULL ){
		print_warning( "packet.c: free_rr_entry() --> p_rr_entry == NULL\n" );
		return;
	}

	if ( p_rr_entry != NULL ){
		if ( p_rr_entry->p_rr_data != NULL ){
			free( p_rr_entry->p_rr_data );
		}

		free( p_rr_entry );
	}
}

void print_packet( PACKET* p_packet ){
    if ( p_packet == NULL ) {
        print_warning( "packet.c: print_packet() --> p_packet == NULL\n" );
        return;
    }

    if ( p_packet->size == 0 ) {
        print_debug( "packet.c: print_packet() --> p_packet->size == 0\n" );
        return;
    }

	printf("----PACKET (total size = %d, count = %d)----\n", p_packet->size, counter++ );
	print_ethernet_header( p_packet );

	if ( is_arp_packet( p_packet ) ){ return print_arp_header( p_packet ); }

    if ( is_ip4_packet( p_packet ) ){
    	print_ip4_header( p_packet );

    	if ( is_udp_packet( p_packet ) ){
			print_udp_header( p_packet );  
				
			if ( is_dns_packet( p_packet ) ){
				print_dns_header( p_packet );
				return;
			} else{
				printf("        DNS: [NOT PORT 53, ABORTING], \n" ); 
				printf("-----------------\n" ); 
				return;
			}

			return;
		}
    	
    	if ( is_tcp_packet( p_packet ) ){
    		print_tcp_header( p_packet );  

    		if ( is_dns_packet( p_packet ) ){
    			print_dns_header( p_packet );
    			return;
    		} else{
				printf("        DNS: [NOT PORT 53, ABORTING], \n" ); 
				printf("-----------------\n" ); 
				return;
    		}

    		return;
    	}

    	printf("        IP4: [NOT UDP OR TCP, ABORTING], \n" ); 
    	printf("-----------------\n" ); 
    	return;
    }

	printf("        IP4: [NOT ARP OR IP4, ABORTING], \n" ); 
	printf("-----------------\n" ); 
	return;
}

static void print_ethernet_header( PACKET *p_packet ){
	ETHERNET_HEADER *p_ethernet_header = get_ethernet_header( p_packet );
	uint8_t *p_MAC_dst = p_ethernet_header->MAC_dst;
	uint8_t *p_MAC_src = p_ethernet_header->MAC_src;
    
    printf("   ETHERNET: MAC_dst       --> %s\n", get_MAC_address( p_MAC_dst ) );
    printf("   ETHERNET: MAC_src       --> %s\n", get_MAC_address( p_MAC_src ) );
	printf("   ETHERNET: type          --> %s\n", get_ethernet_type_name( p_packet ) ); 
}

static void print_arp_header( PACKET *p_packet ){
	ARP_HEADER *p_arp_header = get_arp_header( p_packet );

	printf("        ARP: hardware_type --> %d\n", p_arp_header->hardware_type );
	printf("        ARP: protocol_type --> %d\n", p_arp_header->hardware_size );
	printf("        ARP: hardware_size --> %d\n", p_arp_header->hardware_size );
	printf("        ARP: protocol_size --> %d\n", p_arp_header->protocol_size );
	printf("        ARP: opcode        --> %d\n", p_arp_header->opcode );
	printf("        ARP: MAC_src       --> %s\n", get_MAC_address( p_arp_header->MAC_src ) );
	printf("        ARP: IP4_src       --> %s\n", get_IP4_address( p_arp_header->IP4_src ) );
 	printf("        ARP: MAC_src       --> %s\n", get_MAC_address( p_arp_header->MAC_dst ) );
    printf("        ARP: IP4_dst       --> %s\n", get_IP4_address( p_arp_header->IP4_dst ) );
    printf("-----------------\n" ); 
	return;
}

static void print_ip4_header( PACKET *p_packet ){
	IP4_HEADER *p_ip4_header = get_IP4_header( p_packet );
	uint8_t *p_IP4_dst = p_ip4_header->IP4_dst;
	uint8_t *p_IP4_src = p_ip4_header->IP4_src;

    printf("        IP4: ip4_dst       --> %s\n", get_IP4_address( p_IP4_dst ) );
    printf("        IP4: ip4_src       --> %s\n", get_IP4_address( p_IP4_src ) );
    printf("        IP4: size          --> %d [IHL = %d]\n", get_IP4_header_size( p_ip4_header ), get_ip4_IHL( p_packet ) ); 
    printf("        IP4: protocol      --> %s\n", get_IP4_protocol_name( p_packet ) );

}

static void print_udp_header( PACKET *p_packet ){
	UDP_HEADER *p_udp_header = get_UDP_header( p_packet );
	printf("        UDP: port_dst      --> %d\n", p_udp_header->port_dst ); 
	printf("        UDP: port_src      --> %d\n", p_udp_header->port_src ); 
	printf("        UDP: size          --> %d\n", get_udp_header_size() ); 
	return;
}

static void print_tcp_header( PACKET *p_packet ){
	TCP_HEADER *p_tcp_header = get_TCP_header( p_packet );
	printf("        TCP: port_dst      --> %d\n", p_tcp_header->port_dst ); 
	printf("        TCP: port_src      --> %d\n", p_tcp_header->port_src ); 
	printf("        TCP: size          --> %d [data_offset = %d]\n", get_tcp_header_size( p_tcp_header ), p_tcp_header->data_offset ); 
	return;
}

static void print_dns_header( PACKET *p_packet ){
	DNS_HEADER *p_dns_header = get_DNS_header( p_packet );

	if ( PRINT_MODE_FULL ){
    	printf("        DNS: id            --> %d\n", p_dns_header->identification ); 
    	printf("        DNS: QR            --> %d\n", p_dns_header->QR ); 
    	printf("        DNS: opcode        --> %d\n", p_dns_header->opcode ); 
    	printf("        DNS: AA            --> %d\n", p_dns_header->AA ); 
    	printf("        DNS: TC            --> %d\n", p_dns_header->TC ); 
    	printf("        DNS: RD            --> %d\n", p_dns_header->RD ); 
    	printf("        DNS: RA            --> %d\n", p_dns_header->RA ); 
    	printf("        DNS: Z             --> %d\n", p_dns_header->Z ); 
    	printf("        DNS: AD            --> %d\n", p_dns_header->AD ); 
    	printf("        DNS: CD            --> %d\n", p_dns_header->CD ); 
    	printf("        DNS: rcode         --> %d\n", p_dns_header->rcode ); 
	}

	printf("        DNS: #query        --> %d\n", p_dns_header->query_count ); 
	printf("        DNS: #answer       --> %d\n", p_dns_header->answer_count ); 
	printf("        DNS: #authority    --> %d\n", p_dns_header->authority_count ); 
	printf("        DNS: #additional   --> %d\n", p_dns_header->additional_count ); 

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
	return;
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
	return;
}

static void print_rr_entry_a( uint8_t *p_data ){
	if ( p_data == NULL ) {
        print_warning( "packet.c: print_rr_entry_a() --> p_data == NULL\n" );
        return;
    }

	printf("           : %s\n", get_IP4_address( p_data ) );
	return;
}

static void print_rr_entry_ns( uint8_t *p_data, uint32_t length ){
	if ( p_data == NULL ) {
        print_warning( "packet.c: print_rr_entry_ns() --> p_data == NULL\n" );
        return;
    }

	printf("           : %s\n", get_domain_name( (char*) p_data, length) );
	return;
}

static void print_rr_entry_cname( uint8_t *p_data, uint32_t length ){
	if ( p_data == NULL ) {
        print_warning( "packet.c: print_rr_entry_cname() --> p_data == NULL\n" );
        return;
    }

	printf("           : %s\n", get_domain_name( (char*) p_data, length ) );
	return;
}

static void print_rr_entry_soa( uint8_t *p_data, uint32_t length ){
	if ( p_data == NULL ) {
        print_warning( "packet.c: print_rr_entry_soa() --> p_data == NULL\n" );
        return;
    }

	printf("           : mname = TODO\n"/*, get_domain_name( (char*) p_data, 999 ) */);
	printf("           : rname = TODO\n"/*, get_domain_name( (char*) p_data, 999 )*/ );

	printf("           : serial = 0x%08x\n", get_uint32_t( &p_data[ length - 16 ] ) ); 
	printf("           : refresh = 0x%08x\n", get_uint32_t( &p_data[ length - 12 ]  ) ); 
	printf("           : retry = 0x%08x\n", get_uint32_t( &p_data[ length - 8 ]  ) ); 
	printf("           : expire = 0x%08x\n", get_uint32_t( &p_data[ length - 4 ]  ) ); 
	return;
}

static void print_rr_entry_ptr( uint8_t *p_data, uint32_t length ){
	if ( p_data == NULL ) {
        print_warning( "packet.c: print_rr_entry_ptr() --> p_data == NULL\n" );
        return;
    }

	printf("           : ptr = %s\n", get_domain_name( (char*) p_data, length ) );
	return;
}

static void print_rr_entry_mx( uint8_t *p_data, uint32_t length ){
	if ( p_data == NULL ) {
        print_warning( "packet.c: print_rr_entry_mx() --> p_data == NULL\n" );
        return;
    }

	printf("           : preferences = %d\n", get_uint32_t( p_data ) ); 
	printf("           : exhange = %s\n", get_domain_name( (char*) &p_data[2], length ) );
	return;
}

static void print_rr_entry_txt( uint8_t *p_data, uint32_t length ){
	if ( p_data == NULL ) {
        print_warning( "packet.c: print_rr_entry_txt() --> p_data == NULL\n" );
        return;
    }

	printf("           : txt = %s\n", get_domain_name( (char*) p_data, length ) );
	return;
}







