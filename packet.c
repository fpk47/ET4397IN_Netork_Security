#include "packet.h"
#include "message.h"
#include "tools.h"

static uint8_t MAC_broadcast[6]; 

static int counter = 0;
static uint32_t unique_ID = 0;

static void print_ethernet_header( PACKET *p_packet );
static void print_ARP_header( PACKET *p_packet );
static void print_IP4_header( PACKET *p_packet );
static void print_UDP_header( PACKET *p_packet );
static void print_TCP_header( PACKET *p_packet );
static void print_DNS_header( PACKET *p_packet );

static void print_rr_entry( RR_ENTRY *p_rr_entry, uint32_t rr_entry_index );
static void print_rr_entry_a( uint8_t *p_data );
static void print_rr_entry_ns( uint8_t *p_data, uint32_t length );
static void print_rr_entry_cname( uint8_t *p_data, uint32_t length );
static void print_rr_entry_soa( uint8_t *p_data, uint32_t length  );
static void print_rr_entry_ptr( uint8_t *p_data, uint32_t length );
static void print_rr_entry_mx( uint8_t *p_data, uint32_t length );
static void print_rr_entry_txt( uint8_t *p_data, uint32_t length );

void init_packet( void ){
	for ( int i = 0; i < 6; i++ ){
		MAC_broadcast[i] = 0xff;
	}
}

uint8_t* get_MAC_broadcast(){
	for ( int i = 0; i < 6; i++ ){
		MAC_broadcast[i] = 0xff;
	}

	return MAC_broadcast;
}

uint32_t compare_MAC( uint8_t* p_MAC_1, uint8_t* p_MAC_2 ){
	if ( p_MAC_1 == NULL ){
		print_warning( "packet.c: compare_MAC() --> p_MAC_1 == NULL\n" );
		return FALSE;
	}

	if ( p_MAC_2 == NULL ){
		print_warning( "packet.c: compare_MAC() --> p_MAC_2 == NULL\n" );
		return FALSE;
	}

	for ( int i = 0; i < 6; i++ ){
		if ( p_MAC_1[i] != p_MAC_2[i] ){
			return FALSE;
		}
	}

	return TRUE;
}

uint32_t compare_IP4( uint8_t* p_IP4_1, uint8_t* p_IP4_2 ){
	if ( p_IP4_1 == NULL ){
		print_warning( "packet.c: compare_MAC() --> p_IP4_1 == NULL\n" );
		return FALSE;
	}

	if ( p_IP4_2 == NULL ){
		print_warning( "packet.c: compare_MAC() --> p_IP4_2 == NULL\n" );
		return FALSE;
	}

	for ( int i = 0; i < 4; i++ ){
		if ( p_IP4_1[i] != p_IP4_2[i] ){
			return FALSE;
		}
	}

	return TRUE;
}

uint32_t get_ethernet_header_size( void ){ return 14; }

uint32_t get_IP4_header_size( IP4_HEADER *p_IP4_header ){
	if ( p_IP4_header == NULL ){
		print_warning( "packet.c: get_IP4_header_size() --> p_IP4_header == NULL\n" );
		return -1;
	}

	return ( p_IP4_header->IHL ) * 4; 
}

uint32_t get_ARP_header_size( void ){ return 28; }
uint32_t get_UDP_header_size(){ return 8; }
uint32_t get_TCP_header_size( TCP_HEADER *p_TCP_header ){ return ( p_TCP_header->data_offset ) * 4; }
uint32_t get_DNS_header_size( void ){ return 12; }
uint32_t get_rr_entry_size( RR_ENTRY *p_rr_entry ){ return p_rr_entry->length + 12; }

uint32_t is_ARP_request( PACKET *p_packet ){
	if ( p_packet == NULL ){
		print_warning( "packet.c: is_ARP_request() --> p_packet == NULL\n" );
		return FALSE;
	}

	if ( !has_ARP_header( p_packet ) ){
		print_warning( "packet.c: is_ARP_request() --> has_ARP_header( p_packet ) == FALSE\n" );
		return -1;
	}

	if ( get_ARP_opcode( p_packet ) == TYPE_ARP_REQUEST ){
		return TRUE;
	} else{
		return FALSE;
	}
}

uint32_t is_ARP_reply( PACKET *p_packet ){
	if ( p_packet == NULL ){
		print_warning( "packet.c: is_ARP_reply() --> p_packet == NULL\n" );
		return FALSE;
	}

	if ( !has_ARP_header( p_packet ) ){
		print_warning( "packet.c: is_ARP_reply() --> has_ARP_header( p_packet ) == FALSE\n" );
		return -1;
	}

	if ( get_ARP_opcode( p_packet ) == TYPE_ARP_REPLY ){
		return TRUE;
	} else{
		return FALSE;
	}
}

char* get_ARP_opcode_name( PACKET *p_packet ){
	static char text[100];

	if ( p_packet == NULL ){
		print_warning( "packet.c: get_ARP_opcode() --> p_packet == NULL\n" );
		return NULL;
	}

	uint8_t opcode = get_ARP_opcode( p_packet );

	if ( opcode == TYPE_ARP_REQUEST )   { sprintf( text, "REQUEST"    ); }
	else if ( opcode == TYPE_ARP_REPLY ){ sprintf( text, "REPLY" 	  ); }
	else 				  				{ sprintf( text, "%d", opcode ); }

	return text;
}

uint8_t get_ARP_opcode( PACKET *p_packet ){
	if ( p_packet == NULL ){
		print_warning( "packet.c: get_ARP_opcode() --> p_packet == NULL\n" );
		return -1;
	}

	if ( !has_ARP_header( p_packet ) ){
		print_warning( "packet.c: get_ARP_opcode() --> has_ARP_header( p_packet ) == FALSE\n" );
		return -1;
	}

	ARP_HEADER *p_ARP_header = get_ARP_header( p_packet );
	return p_ARP_header->opcode;
}

uint8_t* get_ARP_MAC_src( PACKET *p_packet ){
	if ( p_packet == NULL ){
		print_warning( "packet.c: get_ARP_MAC_src() --> p_packet == NULL\n" );
		return NULL;
	}

	if ( !has_ARP_header( p_packet ) ){
		print_warning( "packet.c: get_ARP_MAC_src() --> has_ARP_header( p_packet ) == FALSE\n" );
		return NULL;
	}

	ARP_HEADER *p_ARP_header = get_ARP_header( p_packet );
	return p_ARP_header->MAC_src;
}

uint8_t* get_ARP_IP4_src( PACKET *p_packet ){
	if ( p_packet == NULL ){
		print_warning( "packet.c: get_ARP_IP4_src() --> p_packet == NULL\n" );
		return NULL;
	}

	if ( !has_ARP_header( p_packet ) ){
		print_warning( "packet.c: get_ARP_IP4_src() --> has_ARP_header( p_packet ) == FALSE\n" );
		return NULL;
	}

	ARP_HEADER *p_ARP_header = get_ARP_header( p_packet );
	return p_ARP_header->IP4_src;
}

uint8_t* get_ARP_MAC_dst( PACKET *p_packet ){
	if ( p_packet == NULL ){
		print_warning( "packet.c: get_ARP_MAC_dst() --> p_packet == NULL\n" );
		return NULL;
	}

	if ( !has_ARP_header( p_packet ) ){
		print_warning( "packet.c: get_ARP_MAC_dst() --> has_ARP_header( p_packet ) == FALSE\n" );
		return NULL;
	}

	ARP_HEADER *p_ARP_header = get_ARP_header( p_packet );
	return p_ARP_header->MAC_dst;
}

uint8_t* get_ARP_IP4_dst( PACKET *p_packet ){
	if ( p_packet == NULL ){
		print_warning( "packet.c: get_ARP_IP4_dst() --> p_packet == NULL\n" );
		return NULL;
	}

	if ( !has_ARP_header( p_packet ) ){
		print_warning( "packet.c: get_ARP_IP4_dst() --> has_ARP_header( p_packet ) == FALSE\n" );
		return NULL;
	}

	ARP_HEADER *p_ARP_header = get_ARP_header( p_packet );
	return p_ARP_header->IP4_dst;
}

char* get_ethernet_type_name( PACKET* p_packet ){ 
	static char text[100];

	if ( has_ARP_header( p_packet ) ){
		sprintf( text, "ARP" );
	} else if ( has_IP4_header( p_packet ) ){
		sprintf( text, "IP4" );
	} else if ( has_IP6_header( p_packet ) ){
		sprintf( text, "IP6" );
	} else{
		sprintf( text, "%02x", get_IP4_protocol( p_packet ) );
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

	if ( has_UDP_header( p_packet ) ){
		sprintf( text, "UDP" );
	} else if ( has_TCP_header( p_packet ) ){
		sprintf( text, "IP4" );
	} else{
		sprintf( text, "%x", get_IP4_protocol( p_packet ) );
	}
	
	return text;
}

uint8_t get_IP4_protocol( PACKET* p_packet ){
	if ( p_packet == NULL ){
		print_warning( "packet.c: get_IP4_protocol() --> p_packet == NULL\n" );
		return -1;
	}

 	return p_packet->IP4_header.protocol; 
}

uint8_t get_IP4_IHL( PACKET *p_packet ){
		if ( p_packet == NULL ){
		print_warning( "packet.c: get_IP4_protocol() --> p_packet == NULL\n" );
		return -1;
	}

	return p_packet->IP4_header.IHL;
}

uint32_t get_DNS_number_of_queries( PACKET* p_packet ){ 
	if ( p_packet == NULL ){
		print_warning( "packet.c: get_DNS_number_of_queries() --> p_packet == NULL\n" );
		return -1;
	}

	return p_packet->DNS_header.query_count; 
}

uint32_t get_DNS_number_of_answers( PACKET* p_packet ){ 
	if ( p_packet == NULL ){
		print_warning( "packet.c: get_DNS_number_of_answers() --> p_packet == NULL\n" );
		return -1;
	}

	return p_packet->DNS_header.answer_count; 
}

uint32_t get_DNS_number_of_authorities( PACKET* p_packet ){
	if ( p_packet == NULL ){
		print_warning( "packet.c: get_DNS_number_of_authorities() --> p_packet == NULL\n" );
		return -1;
	}

	 return p_packet->DNS_header.authority_count; 
}

uint32_t get_DNS_number_of_additionals( PACKET* p_packet ){
	if ( p_packet == NULL ){
		print_warning( "packet.c: get_DNS_number_of_additionals() --> p_packet == NULL\n" );
		return -1;
	}

	 return p_packet->DNS_header.additional_count; 
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
ARP_HEADER *get_ARP_header( PACKET *p_packet ){ return (ARP_HEADER*) &(p_packet->ARP_header); }
IP4_HEADER* get_IP4_header( PACKET *p_packet ){ return (IP4_HEADER*) &(p_packet->IP4_header); }
UDP_HEADER* get_UDP_header( PACKET *p_packet ){ return (UDP_HEADER*) &(p_packet->UDP_header); }
TCP_HEADER* get_TCP_header( PACKET *p_packet ){ return (TCP_HEADER*) &(p_packet->TCP_header); }
DNS_HEADER* get_DNS_header( PACKET *p_packet ){ return (DNS_HEADER*) &(p_packet->DNS_header); }
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

uint8_t has_IP4_header( PACKET *p_packet ){
	if ( p_packet == NULL ){
		print_warning( "packet.c: has_ARP_header() --> p_packet == NULL\n" );
		return FALSE;
	}

	if ( get_ethernet_type( p_packet ) == TYPE_IP4 ){
		return TRUE;
	} else{
		return FALSE;
	}
}

uint8_t has_IP6_header( PACKET *p_packet ){
	if ( p_packet == NULL ){
		print_warning( "packet.c: hz() --> p_packet == NULL\n" );
		return FALSE;
	}

	if ( get_ethernet_type( p_packet ) == TYPE_IP6 ){
		return TRUE;
	} else{
		return FALSE;
	}
}

uint8_t has_ARP_header( PACKET *p_packet ){
	if ( p_packet == NULL ){
		print_warning( "packet.c: has_ARP_header() --> p_packet == NULL\n" );
		return FALSE;
	}

	if ( get_ethernet_type( p_packet ) == TYPE_ARP ){
		ARP_HEADER *p_ARP_header = get_ARP_header( p_packet );

		if ( p_ARP_header->hardware_size != 6 ){
			print_debug( "packet.c: has_ARP_header() --> hardware_size != 6\n" );
			return FALSE;
		}

		if ( p_ARP_header->protocol_size != 4 ){
			print_debug( "packet.c: has_ARP_header() --> protocol_size != 4\n" );
			return FALSE;
		}

		return TRUE;
	} else{
		return FALSE;
	}
}

uint8_t has_UDP_header( PACKET *p_packet ){
	if ( p_packet == NULL ){
		print_warning( "packet.c: has_UDP_header() --> p_packet == NULL\n" );
		return FALSE;
	}

	if ( !has_IP4_header( p_packet ) ){
		return FALSE;
	}

	if ( p_packet->IP4_header.protocol == TYPE_UDP ){
		return TRUE;
	} else{
		return FALSE;
	}
}

uint8_t has_TCP_header( PACKET *p_packet ){
	if ( p_packet == NULL ){
		print_warning( "packet.c: has_TCP_header() --> p_packet == NULL\n" );
		return FALSE;
	}

	if ( !has_IP4_header( p_packet ) ){
		return FALSE;
	}

	if ( p_packet->IP4_header.protocol == TYPE_TCP ){
		return TRUE;
	} else{
		return FALSE;
	}
}

uint8_t has_DNS_header( PACKET *p_packet ){
	if ( p_packet == NULL ){
		print_warning( "packet.c: has_DNS_header() --> p_packet == NULL\n" );
		return FALSE;
	}

	if ( has_UDP_header( p_packet ) ){
		if ( p_packet->UDP_header.port_dst == 53 || p_packet->UDP_header.port_src == 53 ) return TRUE;
	} else if ( has_TCP_header( p_packet ) ){
		if ( p_packet->TCP_header.port_dst == 53 || p_packet->TCP_header.port_src == 53 ) return TRUE;
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

	for ( int i = 0; i < PACKET_TEXT_SIZE; i++ ){
		p_packet->text[i] = 0;
	}
	
	p_packet->unique_ID = unique_ID++;
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

	for ( int i = 0; i < PACKET_TEXT_SIZE; i++ ){
		p_packet->text[i] = 0;
	}

	p_packet->unique_ID = unique_ID++;
	p_packet->p_data = (uint8_t*) malloc( size );
	p_packet->size = size;

	for( int i = 0; i < size; i++ ){
		p_packet->p_data[i] = p_data[i];
	}

	for( int i = 0; i < NUMBER_OF_RR_ENTRIES; i++ ){
		p_packet->p_rr_entries[i] = NULL;
	}

	return p_packet;
}

void free_packet( PACKET* p_packet ){
	if ( p_packet == NULL ){
		print_warning( "packet.c: free_packet() --> p_packet == NULL\n" );
		return;
	}

	if ( has_DNS_header( p_packet ) ){
		for ( int i = 0; i < NUMBER_OF_RR_ENTRIES; i++ ){
			if ( p_packet->p_rr_entries[i] != NULL ){
				free_rr_entry( p_packet->p_rr_entries[i] );
			}
		}
	}


	free( p_packet->p_data );
	free( p_packet );
}

void set_packet_text( PACKET* p_packet, char *p_text ){
	if ( p_packet == NULL ){
		print_warning( "packet.c: set_packet_text() --> p_packet == NULL\n" );
		return;
	}

	sprintf( p_packet->text, "%s", p_text );
}

char* get_packet_text( PACKET* p_packet ){
	if ( p_packet == NULL ){
		print_warning( "packet.c: set_packet_text() --> p_packet == NULL\n" );
		return NULL;
	}

	return p_packet->text;
}

PACKET* clone_packet( PACKET* p_packet ){
	if ( p_packet == NULL ){
		print_warning( "packet.c: clone_packet() --> p_packet == NULL\n" );
		return NULL;
	}

	PACKET *p_temp_packet = init_packet_uint8_t( p_packet->size, p_packet->p_data );
	p_temp_packet->unique_ID = p_packet->unique_ID;

	sprintf( p_temp_packet->text, "%s", p_packet->text );

	return p_temp_packet;
}

uint32_t compare_packets( PACKET* p_packet_1, PACKET* p_packet_2 ){
	if ( p_packet_1 == NULL ){
		print_warning( "packet.c: compare_packets() --> p_packet_1 == NULL\n" );
		return FALSE;
	}

	if ( p_packet_2 == NULL ){
		print_warning( "packet.c: compare_packets() --> p_packet_2 == NULL\n" );
		return FALSE;
	}

	if ( p_packet_1->unique_ID == p_packet_2->unique_ID ){
		return TRUE;
	} else{
		return FALSE;
	}
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
	printf("    MESSAGE: %s\n", get_packet_text( p_packet ) ); 
	print_ethernet_header( p_packet );

	if ( has_ARP_header( p_packet ) ){ return print_ARP_header( p_packet ); }

    if ( has_IP4_header( p_packet ) ){
    	print_IP4_header( p_packet );

    	if ( has_UDP_header( p_packet ) ){
			print_UDP_header( p_packet );  
				
			if ( has_DNS_header( p_packet ) ){
				print_DNS_header( p_packet );
				return;
			} else{
				printf("        DNS: [NOT PORT 53, ABORTING], \n" ); 
				printf("-----------------\n" ); 
				return;
			}

			return;
		}
    	
    	if ( has_TCP_header( p_packet ) ){
    		print_TCP_header( p_packet );  

    		if ( has_DNS_header( p_packet ) ){
    			print_DNS_header( p_packet );
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
    
    printf("   ETHERNET: MAC_dst       --> %s\n", get_MAC_address_name( p_MAC_dst ) );
    printf("   ETHERNET: MAC_src       --> %s\n", get_MAC_address_name( p_MAC_src ) );
	printf("   ETHERNET: type          --> %s\n", get_ethernet_type_name( p_packet ) ); 
}

static void print_ARP_header( PACKET *p_packet ){
	ARP_HEADER *p_ARP_header = get_ARP_header( p_packet );

	printf("        ARP: hardware_type --> %d\n", p_ARP_header->hardware_type );
	printf("        ARP: protocol_type --> %d\n", p_ARP_header->hardware_size );
	printf("        ARP: hardware_size --> %d\n", p_ARP_header->hardware_size );
	printf("        ARP: protocol_size --> %d\n", p_ARP_header->protocol_size );
	printf("        ARP: opcode        --> %s\n", get_ARP_opcode_name( p_packet ) );
	printf("        ARP: MAC_src       --> %s\n", get_MAC_address_name( p_ARP_header->MAC_src ) );
	printf("        ARP: IP4_src       --> %s\n", get_IP4_address_name( p_ARP_header->IP4_src ) );
 	printf("        ARP: MAC_dst       --> %s\n", get_MAC_address_name( p_ARP_header->MAC_dst ) );
    printf("        ARP: IP4_dst       --> %s\n", get_IP4_address_name( p_ARP_header->IP4_dst ) );
    printf("-----------------\n" ); 
	return;
}

static void print_IP4_header( PACKET *p_packet ){
	IP4_HEADER *p_IP4_header = get_IP4_header( p_packet );
	uint8_t *p_IP4_dst = p_IP4_header->IP4_dst;
	uint8_t *p_IP4_src = p_IP4_header->IP4_src;

    printf("        IP4: IP4_dst       --> %s\n", get_IP4_address_name( p_IP4_dst ) );
    printf("        IP4: IP4_src       --> %s\n", get_IP4_address_name( p_IP4_src ) );
    printf("        IP4: size          --> %d [IHL = %d]\n", get_IP4_header_size( p_IP4_header ), get_IP4_IHL( p_packet ) ); 
    printf("        IP4: protocol      --> %s\n", get_IP4_protocol_name( p_packet ) );

}

static void print_UDP_header( PACKET *p_packet ){
	UDP_HEADER *p_UDP_header = get_UDP_header( p_packet );
	printf("        UDP: port_dst      --> %d\n", p_UDP_header->port_dst ); 
	printf("        UDP: port_src      --> %d\n", p_UDP_header->port_src ); 
	printf("        UDP: size          --> %d\n", get_UDP_header_size() ); 
	return;
}

static void print_TCP_header( PACKET *p_packet ){
	TCP_HEADER *p_TCP_header = get_TCP_header( p_packet );
	printf("        TCP: port_dst      --> %d\n", p_TCP_header->port_dst ); 
	printf("        TCP: port_src      --> %d\n", p_TCP_header->port_src ); 
	printf("        TCP: size          --> %d [data_offset = %d]\n", get_TCP_header_size( p_TCP_header ), p_TCP_header->data_offset ); 
	return;
}

static void print_DNS_header( PACKET *p_packet ){
	DNS_HEADER *p_DNS_header = get_DNS_header( p_packet );

	if ( PRINT_MODE_FULL ){
    	printf("        DNS: id            --> %d\n", p_DNS_header->identification ); 
    	printf("        DNS: QR            --> %d\n", p_DNS_header->QR ); 
    	printf("        DNS: opcode        --> %d\n", p_DNS_header->opcode ); 
    	printf("        DNS: AA            --> %d\n", p_DNS_header->AA ); 
    	printf("        DNS: TC            --> %d\n", p_DNS_header->TC ); 
    	printf("        DNS: RD            --> %d\n", p_DNS_header->RD ); 
    	printf("        DNS: RA            --> %d\n", p_DNS_header->RA ); 
    	printf("        DNS: Z             --> %d\n", p_DNS_header->Z ); 
    	printf("        DNS: AD            --> %d\n", p_DNS_header->AD ); 
    	printf("        DNS: CD            --> %d\n", p_DNS_header->CD ); 
    	printf("        DNS: rcode         --> %d\n", p_DNS_header->rcode ); 
	}

	printf("        DNS: #query        --> %d\n", p_DNS_header->query_count ); 
	printf("        DNS: #answer       --> %d\n", p_DNS_header->answer_count ); 
	printf("        DNS: #authority    --> %d\n", p_DNS_header->authority_count ); 
	printf("        DNS: #additional   --> %d\n", p_DNS_header->additional_count ); 

	RR_QUERY_ENTRY *p_rr_query_entry = get_rr_query_entry( p_packet );

    if ( get_DNS_number_of_queries( p_packet ) == 1 ){
    	printf("        DNS: {QUERY} TYPE %s, CLASS %s, %s\n", get_rr_query_entry_rr_type_name( p_rr_query_entry ), get_rr_query_entry_rr_class_name( p_rr_query_entry ), get_domain_name( p_rr_query_entry->name, 999 ) ); 
    } else if ( get_DNS_number_of_queries( p_packet ) == 1  && get_rr_query_entry_rr_type_name( p_rr_query_entry ) == NULL ){
		printf("        DNS: {QUERY} TYPE %d, CLASS %s, %s\n", p_rr_query_entry->rr_type, get_rr_query_entry_rr_class_name( p_rr_query_entry ), get_domain_name( p_rr_query_entry->name, 999 ) ); 
    } else{
    	printf("        DNS: [#query != 1, ABORTING]\n" );
    	printf("-----------------\n" ); 
    	return;
    }

    uint32_t rr_entry_index = 0;

    for ( int i = 0; i < get_DNS_number_of_answers( p_packet ); i++ ){
		print_rr_entry( p_packet->p_rr_entries[rr_entry_index], rr_entry_index );
		rr_entry_index++;
	}

	for ( int i = 0; i < get_DNS_number_of_authorities( p_packet ); i++ ){
		print_rr_entry( p_packet->p_rr_entries[rr_entry_index], rr_entry_index );	
		rr_entry_index++;
	}

	for ( int i = 0; i < get_DNS_number_of_additionals( p_packet ); i++ ){
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

	printf("           : %s\n", get_IP4_address_name( p_data ) );
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







