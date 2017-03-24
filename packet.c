#include "packet.h"
#include "message.h"
#include "tools.h"

static char text[200];
static uint8_t MAC_broadcast[6]; 

static int counter = 0;
static uint32_t unique_ID = 10;

static void print_radio_tap_packet( PACKET *p_packet );
static void print_ethernet_packet( PACKET *p_packet );
static void print_radio_tap_header( PACKET* p_packet );
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

void update_CFS( PACKET *p_packet ){
	if ( p_packet == NULL ){
		print_warning( "packet.c: update_CFS() --> p_packet == NULL\n" );
		return;
	}

	uint8_t *p_data = get_data( p_packet );
	uint32_t index = get_size( p_packet ) - 4;
	uint32_t CRC32 = crc32(0, (const void*) p_data, index );

	memcpy( &(p_data[ index ] ), (void*) &CRC32, 4 );
}

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

uint8_t* get_data( PACKET *p_packet ){
	if ( p_packet == NULL ){
		print_warning( "packet.c: get_data() --> p_packet == NULL\n" );
		return NULL;
	}

	return p_packet->p_data;
}

uint32_t get_size( PACKET *p_packet ){
	if ( p_packet == NULL ){
		print_warning( "packet.c: get_size() --> p_packet == NULL\n" );
		return 0;
	}

	return p_packet->size;
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

uint32_t is_used( PACKET *p_packet ){
	if ( p_packet == NULL ){
		print_warning( "packet.c: is_used() --> p_packet == NULL\n" );
		return FALSE;
	}

	return p_packet->used;
}

void set_used( PACKET *p_packet ){
	if ( p_packet == NULL ){
		print_warning( "packet.c: set_used() --> p_packet == NULL\n" );
		return;
	}

	p_packet->used = TRUE;
}

uint32_t has_radio_tap_src_address( PACKET *p_packet ){
	if ( p_packet == NULL ){
		print_warning( "packet.c: has_radio_tap_src_address() --> p_packet == NULL\n" );
		return 0;
	}

	if ( !is_radio_tap_packet( p_packet ) ){
		print_warning( "packet.c: has_radio_tap_src_address() --> is_radio_tap_packet( p_packet ) == FALSE\n" );
		return 0;
	}

	RADIO_TAP_HEADER* p_radio_tap_header = get_radio_tap_header( p_packet );

	uint8_t to_DS = get_radio_tap_to_DS( p_packet );
	uint8_t from_DS = get_radio_tap_from_DS( p_packet );

	if ( to_DS == 0 && from_DS == 0 ){
		return TRUE;
	} else if ( to_DS == 0 && from_DS == 1 ){
		return TRUE;
	} else if ( to_DS == 1 && from_DS == 0 ){
		return TRUE;
	} else if ( to_DS == 1 && from_DS == 1 ){
		return FALSE;
	} else{
		sprintf( text, "packet.c: has_radio_tap_dst_address() --> to_DS and from_DS pair (%d, %d) wrong for type [%s]\n", to_DS, from_DS, get_radio_tap_type_name( p_packet ) );
		print_warning( text );
		return FALSE;
	}
}

uint32_t has_radio_tap_dst_address( PACKET *p_packet ){
	if ( p_packet == NULL ){
		print_warning( "packet.c: has_radio_tap_dst_address() --> p_packet == NULL\n" );
		return 0;
	}

	if ( !is_radio_tap_packet( p_packet ) ){
		print_warning( "packet.c: has_radio_tap_dst_address() --> is_radio_tap_packet( p_packet ) == FALSE\n" );
		return 0;
	}

	RADIO_TAP_HEADER* p_radio_tap_header = get_radio_tap_header( p_packet );

	uint8_t to_DS = get_radio_tap_to_DS( p_packet );
	uint8_t from_DS = get_radio_tap_from_DS( p_packet );

	if ( to_DS == 0 && from_DS == 0 ){
		return TRUE;
	} else if ( to_DS == 0 && from_DS == 1 ){
		return TRUE;
	} else if ( to_DS == 1 && from_DS == 0 ){
		return TRUE;
	} else if ( to_DS == 1 && from_DS == 1 ){
		return TRUE;
	} else{
		sprintf( text, "packet.c: has_radio_tap_dst_address() --> to_DS and from_DS pair (%d, %d) wrong for type [%s]\n", to_DS, from_DS, get_radio_tap_type_name( p_packet ) );
		print_warning( text );
		return FALSE;
	}
}

uint32_t has_radio_tap_BSSID( PACKET *p_packet ){
	if ( p_packet == NULL ){
		print_warning( "packet.c: has_radio_tap_BSSID() --> p_packet == NULL\n" );
		return 0;
	}

	if ( !is_radio_tap_packet( p_packet ) ){
		print_warning( "packet.c: has_radio_tap_BSSID() --> is_radio_tap_packet( p_packet ) == FALSE\n" );
		return 0;
	}

	RADIO_TAP_HEADER* p_radio_tap_header = get_radio_tap_header( p_packet );

	uint8_t to_DS = get_radio_tap_to_DS( p_packet );
	uint8_t from_DS = get_radio_tap_from_DS( p_packet );

	if ( to_DS == 0 && from_DS == 0 ){
		return TRUE;
	} else if ( to_DS == 0 && from_DS == 1 ){
		return TRUE;
	} else if ( to_DS == 1 && from_DS == 0 ){
		return TRUE;
	} else if ( to_DS == 1 && from_DS == 1 ){
		return FALSE;
	} else{
		sprintf( text, "packet.c: has_radio_tap_BSSID() --> to_DS and from_DS pair (%d, %d) wrong for type [%s]\n", to_DS, from_DS, get_radio_tap_type_name( p_packet ) );
		print_warning( text );
		return FALSE;
	}
}

uint32_t has_radio_tap_transmission_station_address( PACKET *p_packet ){
	if ( p_packet == NULL ){
		print_warning( "packet.c: has_radio_tap_transmission_station_address() --> p_packet == NULL\n" );
		return 0;
	}

	if ( !is_radio_tap_packet( p_packet ) ){
		print_warning( "packet.c: has_radio_tap_transmission_station_address() --> is_radio_tap_packet( p_packet ) == FALSE\n" );
		return 0;
	}

	RADIO_TAP_HEADER* p_radio_tap_header = get_radio_tap_header( p_packet );

	uint8_t to_DS = get_radio_tap_to_DS( p_packet );
	uint8_t from_DS = get_radio_tap_from_DS( p_packet );

	if ( to_DS == 0 && from_DS == 0 ){
		return FALSE;
	} else if ( to_DS == 0 && from_DS == 1 ){
		return FALSE;
	} else if ( to_DS == 1 && from_DS == 0 ){
		return FALSE;
	} else if ( to_DS == 1 && from_DS == 1 ){
		return TRUE;
	} else{
		sprintf( text, "packet.c: has_radio_tap_transmission_station_address() --> to_DS and from_DS pair (%d, %d) wrong for type [%s]\n", to_DS, from_DS, get_radio_tap_type_name( p_packet ) );
		print_warning( text );
		return FALSE;
	}
}

uint32_t has_radio_tap_receiving_station_address( PACKET *p_packet ){
	if ( p_packet == NULL ){
		print_warning( "packet.c: has_radio_tap_receiving_station_address() --> p_packet == NULL\n" );
		return 0;
	}

	if ( !is_radio_tap_packet( p_packet ) ){
		print_warning( "packet.c: has_radio_tap_receiving_station_address() --> is_radio_tap_packet( p_packet ) == FALSE\n" );
		return 0;
	}

	RADIO_TAP_HEADER* p_radio_tap_header = get_radio_tap_header( p_packet );

	uint8_t to_DS = get_radio_tap_to_DS( p_packet );
	uint8_t from_DS = get_radio_tap_from_DS( p_packet );

	if ( to_DS == 0 && from_DS == 0 ){
		return FALSE;
	} else if ( to_DS == 0 && from_DS == 1 ){
		return FALSE;
	} else if ( to_DS == 1 && from_DS == 0 ){
		return FALSE;
	} else if ( to_DS == 1 && from_DS == 1 ){
		return TRUE;
	} else{
		sprintf( text, "packet.c: has_radio_tap_receiving_station_address() --> to_DS and from_DS pair (%d, %d) wrong for type [%s]\n", to_DS, from_DS, get_radio_tap_type_name( p_packet ) );
		print_warning( text );
		return FALSE;
	}
}


uint8_t* get_radio_tap_src_address( PACKET *p_packet ){
	if ( p_packet == NULL ){
		print_warning( "packet.c: get_radio_tap_src_address() --> p_packet == NULL\n" );
		return 0;
	}

	if ( !is_radio_tap_packet( p_packet ) ){
		print_warning( "packet.c: get_radio_tap_src_address() --> is_radio_tap_packet( p_packet ) == FALSE\n" );
		return 0;
	}

	RADIO_TAP_HEADER* p_radio_tap_header = get_radio_tap_header( p_packet );

	uint8_t to_DS = get_radio_tap_to_DS( p_packet );
	uint8_t from_DS = get_radio_tap_from_DS( p_packet );

	if ( to_DS == 0 && from_DS == 0 ){
		return p_radio_tap_header->src_address;
	} else if ( to_DS == 0 && from_DS == 1 ){
		return p_radio_tap_header->src_address;
	} else if ( to_DS == 1 && from_DS == 0 ){
		return p_radio_tap_header->src_address;
	} else if ( to_DS == 1 && from_DS == 1 ){
		sprintf( text, "packet.c: get_radio_tap_src_address() --> to_DS and from_DS pair (%d, %d) wrong for type [%s]\n", to_DS, from_DS, get_radio_tap_type_name( p_packet ) );
		print_warning( text );
		return NULL;
	} else{
		sprintf( text, "packet.c: get_radio_tap_src_address() --> to_DS and from_DS pair (%d, %d) wrong for type [%s]\n", to_DS, from_DS, get_radio_tap_type_name( p_packet ) );
		print_warning( text );
		return NULL;
	}
}

uint8_t* get_radio_tap_dst_address( PACKET *p_packet ){
	if ( p_packet == NULL ){
		print_warning( "packet.c: get_radio_tap_dst_address() --> p_packet == NULL\n" );
		return 0;
	}

	if ( !is_radio_tap_packet( p_packet ) ){
		print_warning( "packet.c: get_radio_tap_dst_address() --> is_radio_tap_packet( p_packet ) == FALSE\n" );
		return 0;
	}

	RADIO_TAP_HEADER* p_radio_tap_header = get_radio_tap_header( p_packet );

	uint8_t to_DS = get_radio_tap_to_DS( p_packet );
	uint8_t from_DS = get_radio_tap_from_DS( p_packet );

	if ( to_DS == 0 && from_DS == 0 ){
		return p_radio_tap_header->dst_address;
	} else if ( to_DS == 0 && from_DS == 1 ){
		return p_radio_tap_header->dst_address;
	} else if ( to_DS == 1 && from_DS == 0 ){
		return p_radio_tap_header->dst_address;
	} else if ( to_DS == 1 && from_DS == 1 ){
		return p_radio_tap_header->dst_address;
	} else{
		sprintf( text, "packet.c: get_radio_tap_dst_address() --> to_DS and from_DS pair (%d, %d) wrong for type [%s]\n", to_DS, from_DS, get_radio_tap_type_name( p_packet ) );
		print_warning( text );
		return NULL;
	}
}

uint8_t* get_radio_tap_BSSID( PACKET *p_packet ){
	if ( p_packet == NULL ){
		print_warning( "packet.c: get_radio_tap_BSSID() --> p_packet == NULL\n" );
		return 0;
	}

	if ( !is_radio_tap_packet( p_packet ) ){
		print_warning( "packet.c: get_radio_tap_BSSID() --> is_radio_tap_packet( p_packet ) == FALSE\n" );
		return 0;
	}

	RADIO_TAP_HEADER* p_radio_tap_header = get_radio_tap_header( p_packet );

	uint8_t to_DS = get_radio_tap_to_DS( p_packet );
	uint8_t from_DS = get_radio_tap_from_DS( p_packet );

	if ( to_DS == 0 && from_DS == 0 ){
		return p_radio_tap_header->BSSID;
	} else if ( to_DS == 0 && from_DS == 1 ){
		return p_radio_tap_header->BSSID;
	} else if ( to_DS == 1 && from_DS == 0 ){
		return p_radio_tap_header->BSSID;
	} else if ( to_DS == 1 && from_DS == 1 ){
		sprintf( text, "packet.c: get_radio_tap_BSSID() --> to_DS and from_DS pair (%d, %d) wrong for type [%s]\n", to_DS, from_DS, get_radio_tap_type_name( p_packet ) );
		print_warning( text );
		return NULL;
	} else{
		sprintf( text, "packet.c: get_radio_tap_BSSID() --> to_DS and from_DS pair (%d, %d) wrong for type [%s]\n", to_DS, from_DS, get_radio_tap_type_name( p_packet ) );
		print_warning( text );
		return NULL;
	}
}

uint8_t* get_radio_tap_transmission_station_address( PACKET *p_packet ){
	if ( p_packet == NULL ){
		print_warning( "packet.c: get_radio_tap_transmission_station_address() --> p_packet == NULL\n" );
		return 0;
	}

	if ( !is_radio_tap_packet( p_packet ) ){
		print_warning( "packet.c: get_radio_tap_transmission_station_address() --> is_radio_tap_packet( p_packet ) == FALSE\n" );
		return 0;
	}

	RADIO_TAP_HEADER* p_radio_tap_header = get_radio_tap_header( p_packet );

	uint8_t to_DS = get_radio_tap_to_DS( p_packet );
	uint8_t from_DS = get_radio_tap_from_DS( p_packet );

	if ( to_DS == 0 && from_DS == 0 ){
		sprintf( text, "packet.c: get_radio_tap_transmission_station_address() --> to_DS and from_DS pair (%d, %d) wrong for type [%s]\n", to_DS, from_DS, get_radio_tap_type_name( p_packet ) );
		print_warning( text );
		return NULL;
	} else if ( to_DS == 0 && from_DS == 1 ){
		sprintf( text, "packet.c: get_radio_tap_transmission_station_address() --> to_DS and from_DS pair (%d, %d) wrong for type [%s]\n", to_DS, from_DS, get_radio_tap_type_name( p_packet ) );
		print_warning( text );
		return NULL;
	} else if ( to_DS == 1 && from_DS == 0 ){
		sprintf( text, "packet.c: get_radio_tap_transmission_station_address() --> to_DS and from_DS pair (%d, %d) wrong for type [%s]\n", to_DS, from_DS, get_radio_tap_type_name( p_packet ) );
		print_warning( text );
		return NULL;
	} else if ( to_DS == 1 && from_DS == 1 ){
		return p_radio_tap_header->transmission_station_address;
	} else{
		sprintf( text, "packet.c: get_radio_tap_transmission_station_address() --> to_DS and from_DS pair (%d, %d) wrong for type [%s]\n", to_DS, from_DS, get_radio_tap_type_name( p_packet ) );
		print_warning( text );
		return NULL;
	}	
}

uint8_t* get_radio_tap_receiving_station_address( PACKET *p_packet ){
	if ( p_packet == NULL ){
		print_warning( "packet.c: get_radio_tap_receiving_station_address() --> p_packet == NULL\n" );
		return 0;
	}

	if ( !is_radio_tap_packet( p_packet ) ){
		print_warning( "packet.c: get_radio_tap_receiving_station_address() --> is_radio_tap_packet( p_packet ) == FALSE\n" );
		return 0;
	}

	RADIO_TAP_HEADER* p_radio_tap_header = get_radio_tap_header( p_packet );

	uint8_t to_DS = get_radio_tap_to_DS( p_packet );
	uint8_t from_DS = get_radio_tap_from_DS( p_packet );

	if ( to_DS == 0 && from_DS == 0 ){
		sprintf( text, "packet.c: get_radio_tap_receiving_station_address() --> to_DS and from_DS pair (%d, %d) wrong for type [%s]\n", to_DS, from_DS, get_radio_tap_type_name( p_packet ) );
		print_warning( text );
		return NULL;
	} else if ( to_DS == 0 && from_DS == 1 ){
		sprintf( text, "packet.c: get_radio_tap_receiving_station_address() --> to_DS and from_DS pair (%d, %d) wrong for type [%s]\n", to_DS, from_DS, get_radio_tap_type_name( p_packet ) );
		print_warning( text );
		return NULL;
	} else if ( to_DS == 1 && from_DS == 0 ){
		sprintf( text, "packet.c: get_radio_tap_receiving_station_address() --> to_DS and from_DS pair (%d, %d) wrong for type [%s]\n", to_DS, from_DS, get_radio_tap_type_name( p_packet ) );
		print_warning( text );
		return NULL;
	} else if ( to_DS == 1 && from_DS == 1 ){
		return p_radio_tap_header->receiving_station_address;
	} else{
		sprintf( text, "packet.c: get_radio_tap_receiving_station_address() --> to_DS and from_DS pair (%d, %d) wrong for type [%s]\n", to_DS, from_DS, get_radio_tap_type_name( p_packet ) );
		print_warning( text );
		return NULL;
	}
}

uint8_t get_radio_tap_to_DS( PACKET *p_packet ){
	if ( p_packet == NULL ){
		print_warning( "packet.c: get_radio_tap_to_DS() --> p_packet == NULL\n" );
		return 0;
	}

	if ( !is_radio_tap_packet( p_packet ) ){
		print_warning( "packet.c: get_radio_tap_to_DS() --> is_radio_tap_packet( p_packet ) == FALSE\n" );
		return 0;
	}

	RADIO_TAP_HEADER* p_radio_tap_header = get_radio_tap_header( p_packet );

	return p_radio_tap_header->to_DS;
}

uint8_t get_radio_tap_from_DS( PACKET *p_packet ){
	if ( p_packet == NULL ){
		print_warning( "packet.c: get_radio_tap_from_DS() --> p_packet == NULL\n" );
		return 0;
	}

	if ( !is_radio_tap_packet( p_packet ) ){
		print_warning( "packet.c: get_radio_tap_from_DS() --> is_radio_tap_packet( p_packet ) == FALSE\n" );
		return 0;
	}

	RADIO_TAP_HEADER* p_radio_tap_header = get_radio_tap_header( p_packet );

	return p_radio_tap_header->from_DS;
}

uint32_t get_radio_tap_header_size( RADIO_TAP_HEADER *p_radio_tap_header ){
	if ( p_radio_tap_header == NULL ){
		print_warning( "packet.c: get_radio_tap_header_size() --> p_radio_tap_header == NULL\n" );
		return -1;
	}

	return p_radio_tap_header->length;
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

uint16_t get_TCP_port_src( PACKET *p_packet ){
	if ( p_packet == NULL ){
		print_warning( "packet.c: get_TCP_port_src() --> p_packet == NULL\n" );
		return 0;
	}

	if ( is_ethernet_packet( p_packet ) == FALSE ){
		print_warning( "packet.c: get_TCP_port_src() -->  is_ethernet_packet( p_packet ) == FALSE\n" );
		return 0;
	}

	if ( has_TCP_header( p_packet ) == FALSE ){
		print_warning( "packet.c: get_TCP_port_src() -->  has_TCP_header( p_packet ) == FALSE\n" );
		return 0;
	}

	TCP_HEADER *p_TCP_header = get_TCP_header( p_packet );
	return p_TCP_header->port_src;
}

uint16_t get_TCP_port_dst( PACKET *p_packet ){
	if ( p_packet == NULL ){
		print_warning( "packet.c: get_TCP_port_dst() --> p_packet == NULL\n" );
		return 0;
	}

	if ( is_ethernet_packet( p_packet ) == FALSE ){
		print_warning( "packet.c: get_TCP_port_dst() -->  is_ethernet_packet( p_packet ) == FALSE\n" );
		return 0;
	}

	if ( has_TCP_header( p_packet ) == FALSE ){
		print_warning( "packet.c: get_TCP_port_dst() -->  has_TCP_header( p_packet ) == FALSE\n" );
		return 0;
	}

	TCP_HEADER *p_TCP_header = get_TCP_header( p_packet );
	return p_TCP_header->port_dst;
}

void set_TCP_port_src( PACKET *p_packet, uint16_t TCP_port_src ){
	if ( p_packet == NULL ){
		print_warning( "packet.c: set_TCP_port_src() --> p_packet == NULL\n" );
		return;
	}

	if ( is_ethernet_packet( p_packet ) == FALSE ){
		print_warning( "packet.c: set_TCP_port_src() -->  is_ethernet_packet( p_packet ) == FALSE\n" );
		return;
	}

	if ( has_TCP_header( p_packet ) == FALSE ){
		print_warning( "packet.c: set_TCP_port_src() -->  has_TCP_header( p_packet ) == FALSE\n" );
		return;
	}


	IP4_HEADER *p_IP4_header = get_IP4_header( p_packet );
	TCP_HEADER *p_TCP_header = get_TCP_header( p_packet );
	p_TCP_header->port_src = TCP_port_src;

	uint8_t *p_data = get_data( p_packet );
	uint32_t index = get_ethernet_header_size() + get_IP4_header_size( p_IP4_header );
	set_uint16_t( &(p_data[ index + 2 ]), TCP_port_src );
}

void set_TCP_port_dst( PACKET *p_packet, uint16_t TCP_port_dst ){
	if ( p_packet == NULL ){
		print_warning( "packet.c: set_TCP_port_dst() --> p_packet == NULL\n" );
		return;
	}

	if ( is_ethernet_packet( p_packet ) == FALSE ){
		print_warning( "packet.c: set_TCP_port_dst() -->  is_ethernet_packet( p_packet ) == FALSE\n" );
		return;
	}

	if ( has_TCP_header( p_packet ) == FALSE ){
		print_warning( "packet.c: set_TCP_port_dst() -->  has_TCP_header( p_packet ) == FALSE\n" );
		return;
	}

	IP4_HEADER *p_IP4_header = get_IP4_header( p_packet );
	TCP_HEADER *p_TCP_header = get_TCP_header( p_packet );
	p_TCP_header->port_dst = TCP_port_dst;

	uint8_t *p_data = get_data( p_packet );
	uint32_t index = get_ethernet_header_size() + get_IP4_header_size( p_IP4_header );
	set_uint16_t( &(p_data[ index + 0 ]), TCP_port_dst );
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

	if ( is_ethernet_packet( p_packet ) == FALSE ){
		print_warning( "packet.c: is_ethernet_packet() --> is_ethernet_packet( p_packet ) == FALSE\n" );
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

	if ( !has_IP4_header( p_packet ) ){
		print_warning( "packet.c: get_IP4_protocol() --> p_packet has no IP4_HEADER\n" );
		return -1;
	}

 	return p_packet->IP4_header.protocol; 
}

uint8_t get_IP4_IHL( PACKET *p_packet ){
		if ( p_packet == NULL ){
		print_warning( "packet.c: get_IP4_protocol() --> p_packet == NULL\n" );
		return -1;
	}

	if ( !has_IP4_header( p_packet ) ){
		print_warning( "packet.c: get_IP4_IHL() --> p_packet has no IP4_HEADER\n" );
		return -1;
	}

	return p_packet->IP4_header.IHL;
}

uint32_t get_DNS_number_of_queries( PACKET* p_packet ){ 
	if ( p_packet == NULL ){
		print_warning( "packet.c: get_DNS_number_of_queries() --> p_packet == NULL\n" );
		return -1;
	}

	if ( !has_DNS_header( p_packet ) ){
		print_warning( "packet.c: get_DNS_number_of_queries() --> p_packet has no DNS_HEADER\n" );
		return -1;
	}

	return p_packet->DNS_header.query_count; 
}

uint32_t get_DNS_number_of_answers( PACKET* p_packet ){ 
	if ( p_packet == NULL ){
		print_warning( "packet.c: get_DNS_number_of_answers() --> p_packet == NULL\n" );
		return -1;
	}

	if ( !has_DNS_header( p_packet ) ){
		print_warning( "packet.c: get_DNS_number_of_answers() --> p_packet has no DNS_HEADER\n" );
		return -1;
	}

	return p_packet->DNS_header.answer_count; 
}

uint32_t get_DNS_number_of_authorities( PACKET* p_packet ){
	if ( p_packet == NULL ){
		print_warning( "packet.c: get_DNS_number_of_authorities() --> p_packet == NULL\n" );
		return -1;
	}

	if ( !has_DNS_header( p_packet ) ){
		print_warning( "packet.c: get_DNS_number_of_authorities() --> p_packet has no DNS_HEADER\n" );
		return -1;
	}

	 return p_packet->DNS_header.authority_count; 
}

uint32_t get_DNS_number_of_additionals( PACKET* p_packet ){
	if ( p_packet == NULL ){
		print_warning( "packet.c: get_DNS_number_of_additionals() --> p_packet == NULL\n" );
		return -1;
	}

	if ( !has_DNS_header( p_packet ) ){
		print_warning( "packet.c: get_DNS_number_of_additionals() --> p_packet has no DNS_HEADER\n" );
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

RADIO_TAP_HEADER* get_radio_tap_header( PACKET *p_packet ){
	if ( p_packet == NULL ){
		print_warning( "packet.c: get_radio_tap_header() --> p_packet == NULL\n" );
		return NULL;
	}

	return (RADIO_TAP_HEADER*) &(p_packet->radio_tap_header); 
}

ETHERNET_HEADER* get_ethernet_header( PACKET *p_packet ){ 
	if ( p_packet == NULL ){
		print_warning( "packet.c: get_ethernet_header() --> p_packet == NULL\n" );
		return NULL;
	}

	return (ETHERNET_HEADER*) &(p_packet->ethernet_header); 
}

ARP_HEADER *get_ARP_header( PACKET *p_packet ){ 
	if ( p_packet == NULL ){
		print_warning( "packet.c: get_ARP_header() --> p_packet == NULL\n" );
		return NULL;
	}
	
	return (ARP_HEADER*) &(p_packet->ARP_header); 
}

IP4_HEADER* get_IP4_header( PACKET *p_packet ){ 
	if ( p_packet == NULL ){
		print_warning( "packet.c: get_IP4_header() --> p_packet == NULL\n" );
		return NULL;
	}
	
	return (IP4_HEADER*) &(p_packet->IP4_header); 
}

UDP_HEADER* get_UDP_header( PACKET *p_packet ){ 
	if ( p_packet == NULL ){
		print_warning( "packet.c: get_UDP_header() --> p_packet == NULL\n" );
		return NULL;
	}
	
	return (UDP_HEADER*) &(p_packet->UDP_header); 
}

TCP_HEADER* get_TCP_header( PACKET *p_packet ){
	if ( p_packet == NULL ){
		print_warning( "packet.c: get_TCP_header() --> p_packet == NULL\n" );
		return NULL;
	}

	return (TCP_HEADER*) &(p_packet->TCP_header); 
}

DNS_HEADER* get_DNS_header( PACKET *p_packet ){ 
	if ( p_packet == NULL ){
		print_warning( "packet.c: get_DNS_header() --> p_packet == NULL\n" );
		return NULL;
	}
	
	return (DNS_HEADER*) &(p_packet->DNS_header); 
}

RR_QUERY_ENTRY* get_rr_query_entry( PACKET *p_packet ){ 
	return  (RR_QUERY_ENTRY*) &(p_packet->rr_query_entry); 
}

char* get_type_name( PACKET *p_packet ){
	if ( p_packet == NULL ){
		print_warning( "packet.c: get_type_name() --> p_packet == NULL\n" );
		return NULL;
	}

	static char temp_text[100];

	if      ( is_ethernet_packet( p_packet ) ) { sprintf( temp_text, "ETHERNET"  ); }
	else if ( is_radio_tap_packet( p_packet ) ){ sprintf( temp_text, "RADIO_TAP" ); }
	else									   { sprintf( temp_text, "UKNOWN"    ); }   

	return temp_text;
}

uint32_t get_unique_ID( PACKET *p_packet ){
		if ( p_packet == NULL ){
		print_warning( "packet.c: get_unique_ID() --> p_packet == NULL\n" );
		return 0;
	}

	return p_packet->unique_ID;
}

uint32_t get_type( PACKET *p_packet ){
	if ( p_packet == NULL ){
		print_warning( "packet.c: get_type() --> p_packet == NULL\n" );
		return -1;
	}

	return p_packet->type;
}

uint8_t get_radio_tap_type( PACKET *p_packet ){
	if ( p_packet == NULL ){
		print_warning( "packet.c: get_radio_tap_type() --> p_packet == NULL\n" );
		return -1;
	}

	if ( !is_radio_tap_packet( p_packet ) ){
		print_warning( "packet.c: get_radio_tap_type() --> is_radio_tap_packet( p_packet ) == FALSE\n" );
		return -1;
	}

	return p_packet->radio_tap_header.type;
}

char* get_radio_tap_type_name( PACKET *p_packet ){
	if ( p_packet == NULL ){
		print_warning( "packet.c: get_radio_tap_type() --> p_packet == NULL\n" );
		return NULL;
	}

	if ( !is_radio_tap_packet( p_packet ) ){
		print_warning( "packet.c: get_radio_tap_type() --> is_radio_tap_packet( p_packet ) == FALSE\n" );
		return NULL;
	}

	static char temp_text[100];

	uint8_t type = get_radio_tap_type( p_packet );

	if      ( type == 0x00 ) { sprintf( temp_text, "Association Request" ); }
	else if ( type == 0x10 ) { sprintf( temp_text, "Association Response" ); }
	else if ( type == 0x20 ) { sprintf( temp_text, "Reassociation Request" ); }
	else if ( type == 0x30 ) { sprintf( temp_text, "Reassociation Response" ); }
	else if ( type == 0x40 ) { sprintf( temp_text, "Probe Request" ); }
	else if ( type == 0x50 ) { sprintf( temp_text, "Probe Response" ); }
	else if ( type == 0x80 ) { sprintf( temp_text, "Beacon" ); }
	else if ( type == 0x90 ) { sprintf( temp_text, "ATIM" ); }
	else if ( type == 0xA0 ) { sprintf( temp_text, "Disassociation" ); }
	else if ( type == 0xB0 ) { sprintf( temp_text, "Authentication" ); }
	else if ( type == 0xC0 ) { sprintf( temp_text, "Deauthentication" ); }
	else if ( type == 0xD0 ) { sprintf( temp_text, "Action" ); }
	else if ( type == 0x81 ) { sprintf( temp_text, "Block Ack Request" ); }
	else if ( type == 0x91 ) { sprintf( temp_text, "Block Ack" ); }
	else if ( type == 0xA1 ) { sprintf( temp_text, "PS-Poll" ); }
	else if ( type == 0xB1 ) { sprintf( temp_text, "RTS" ); }
	else if ( type == 0xC1 ) { sprintf( temp_text, "CTS" ); }
	else if ( type == 0xD1 ) { sprintf( temp_text, "ACK" ); }
	else if ( type == 0xE1 ) { sprintf( temp_text, "CF-end" ); }
	else if ( type == 0xF1 ) { sprintf( temp_text, "CF-end + CF-ack" ); }
	else if ( type == 0x02 ) { sprintf( temp_text, "Data" ); }
	else if ( type == 0x12 ) { sprintf( temp_text, "Data + CF-ack" ); }
	else if ( type == 0x22 ) { sprintf( temp_text, "Data + CF-poll" ); }
	else if ( type == 0x32 ) { sprintf( temp_text, "Data + CF-ack + CF-poll" ); }
	else if ( type == 0x42 ) { sprintf( temp_text, "Null" ); }
	else if ( type == 0x52 ) { sprintf( temp_text, "CF-ack" ); }
	else if ( type == 0x62 ) { sprintf( temp_text, "CF-poll" ); }
	else if ( type == 0x72 ) { sprintf( temp_text, "CF-ack + CF-poll" ); }
	else if ( type == 0x82 ) { sprintf( temp_text, "QoS data" ); }
	else if ( type == 0x92 ) { sprintf( temp_text, "QoS data + CF-ack" ); }
	else if ( type == 0xA2 ) { sprintf( temp_text, "QoS data + CF-poll" ); }
	else if ( type == 0xB2 ) { sprintf( temp_text, "QoS data + CF-ack + CF-poll" ); }
	else if ( type == 0xD2 ) { sprintf( temp_text, "QoS Null" ); }
	else if ( type == 0xE2 ) { sprintf( temp_text, "QoS + CF-poll (no data)" ); }
	else if ( type == 0xF2 ) { sprintf( temp_text, "Qos + CF-ack (no data)" ); }
	else					 { sprintf( temp_text, "UKNOWN (%02x)", type ); }   

	return temp_text;
}

uint32_t get_radio_tap_length( PACKET *p_packet ){
	if ( p_packet == NULL ){
		print_warning( "packet.c: get_radio_tap_length() --> p_packet == NULL\n" );
		return -1;
	}

	if ( !is_radio_tap_packet( p_packet ) ){
		print_warning( "packet.c: get_radio_tap_length() --> is_radio_tap_packet( p_packet ) == FALSE\n" );
		return -1;
	}

	return p_packet->radio_tap_header.length;
}

uint64_t get_radio_tap_time( PACKET *p_packet ){
	if ( p_packet == NULL ){
		print_warning( "packet.c: get_radio_tap_time() --> p_packet == NULL\n" );
		return -1;
	}

	if ( !is_radio_tap_packet( p_packet ) ){
		print_warning( "packet.c: get_radio_tap_time() --> is_radio_tap_packet( p_packet ) == FALSE\n" );
		return -1;
	}

	return p_packet->radio_tap_header.time;
}

void set_IP4_src( PACKET *p_packet, uint8_t *p_IP4_src ){
	if ( p_packet == NULL ){
		print_warning( "packet.c: get_IP4_MAC_src() --> p_packet == NULL\n" );
		return;
	}

	if ( is_ethernet_packet( p_packet ) == FALSE ){
		print_warning( "packet.c: set_IP4_src() --> is_ethernet_packet( p_packet ) == FALSE\n" );
		return;
	}

	if ( has_IP4_header( p_packet ) == FALSE ){
		print_warning( "packet.c: set_IP4_src() --> has_IP4_header( p_packet ) == FALSE\n" );
		return;
	}

	if ( p_IP4_src == NULL ){
		print_warning( "packet.c: set_IP4_src() --> p_IP4_src == NULL\n" );
		return;
	}

	uint32_t index = get_ethernet_header_size() + 12;
	set_IP4_address( &(p_packet->p_data[ index ]), p_IP4_src );

	IP4_HEADER *p_IP4_header = get_IP4_header( p_packet );

	for ( int i = 0; i < 4; i++ ){
		p_IP4_header->IP4_src[i] = p_IP4_src[i];
	}
}

void set_IP4_dst( PACKET *p_packet, uint8_t *p_IP4_dst ){
	if ( p_packet == NULL ){
		print_warning( "packet.c: set_IP4_dst() --> p_packet == NULL\n" );
		return;
	}

	if ( is_ethernet_packet( p_packet ) == FALSE ){
		print_warning( "packet.c: set_IP4_dst() --> is_ethernet_packet( p_packet ) == FALSE\n" );
		return;
	}

	if ( has_IP4_header( p_packet ) == FALSE ){
		print_warning( "packet.c: set_IP4_dst() --> has_IP4_header( p_packet ) == FALSE\n" );
		return;
	}

	if ( p_IP4_dst == NULL ){
		print_warning( "packet.c: set_IP4_dst() --> p_IP4_dst == NULL\n" );
		return;
	}

	uint32_t index = get_ethernet_header_size() + 16;
	set_IP4_address( &(p_packet->p_data[ index ]), p_IP4_dst );

	IP4_HEADER *p_IP4_header = get_IP4_header( p_packet );

	for ( int i = 0; i < 4; i++ ){
		p_IP4_header->IP4_dst[i] = p_IP4_dst[i];
	}
}

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

void set_MAC_src( PACKET *p_packet, uint8_t *p_MAC_src ){
	if ( p_packet == NULL ){
		print_warning( "packet.c: get_IP4_MAC_src() --> p_packet == NULL\n" );
		return;
	}

	if ( is_ethernet_packet( p_packet ) == FALSE ){
		print_warning( "packet.c: set_IP4_src() --> is_ethernet_packet( p_packet ) == FALSE\n" );
		return;
	}

	if ( p_MAC_src == NULL ){
		print_warning( "packet.c: set_MAC_src() --> p_MAC_src == NULL\n" );
		return;
	}
	
	set_MAC_address( &(p_packet->p_data[ 6 ]), p_MAC_src );
}

void set_MAC_dst( PACKET *p_packet, uint8_t *p_MAC_dst ){
	if ( p_packet == NULL ){
		print_warning( "packet.c: get_IP4_MAC_src() --> p_packet == NULL\n" );
		return;
	}

	if ( is_ethernet_packet( p_packet ) == FALSE ){
		print_warning( "packet.c: set_IP4_src() --> is_ethernet_packet( p_packet ) == FALSE\n" );
		return;
	}

	if ( p_MAC_dst == NULL ){
		print_warning( "packet.c: set_MAC_src() --> p_MAC_dst == NULL\n" );
		return;
	}
	
	set_MAC_address( &(p_packet->p_data[ 0 ]), p_MAC_dst );
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

uint8_t is_radio_tap_packet( PACKET *p_packet ){
	if ( p_packet == NULL ){
		print_warning( "packet.c: is_radio_tap_packet() --> p_packet == NULL\n" );
		return FALSE;
	}

	if ( p_packet->type == TYPE_RADIO_TAP ){
		return TRUE;
	} else{
		return FALSE;	
	}
}

uint8_t is_ethernet_packet( PACKET *p_packet ){
	if ( p_packet == NULL ){
		print_warning( "packet.c: is_ethernet_packet() --> p_packet == NULL\n" );
		return FALSE;
	}

	if ( p_packet->type == TYPE_ETHERNET ){
		return TRUE;
	} else{
		return FALSE;	
	}
}


uint8_t has_IP4_header( PACKET *p_packet ){
	if ( p_packet == NULL ){
		print_warning( "packet.c: has_ARP_header() --> p_packet == NULL\n" );
		return FALSE;
	}

	if ( is_ethernet_packet( p_packet ) ){
		if ( get_ethernet_type( p_packet ) == TYPE_IP4 ){
			return TRUE;
		} else{
			return FALSE;
		}
	} else{
		return FALSE;
	}
}

uint8_t has_IP6_header( PACKET *p_packet ){
	if ( p_packet == NULL ){
		print_warning( "packet.c: hz() --> p_packet == NULL\n" );
		return FALSE;
	}
	if ( is_ethernet_packet( p_packet ) ){
		if ( get_ethernet_type( p_packet ) == TYPE_IP6 ){
			return TRUE;
		} else{
			return FALSE;
		}
	} else{
		return FALSE;
	}
}

uint8_t has_ARP_header( PACKET *p_packet ){
	if ( p_packet == NULL ){
		print_warning( "packet.c: has_ARP_header() --> p_packet == NULL\n" );
		return FALSE;
	}

	if ( is_ethernet_packet( p_packet ) ){
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

	if ( is_ethernet_packet( p_packet ) ){
		if ( p_packet->IP4_header.protocol == TYPE_UDP ){
			return TRUE;
		} else{
			return FALSE;
		}
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

	if ( is_ethernet_packet( p_packet ) ){
		if ( p_packet->IP4_header.protocol == TYPE_TCP ){
			return TRUE;
		} else{
			return FALSE;
		}
	} else{
		return FALSE;
	}
}

uint8_t has_DNS_header( PACKET *p_packet ){
	if ( p_packet == NULL ){
		print_warning( "packet.c: has_DNS_header() --> p_packet == NULL\n" );
		return FALSE;
	}

	if ( is_ethernet_packet( p_packet ) ){
		if ( has_UDP_header( p_packet ) ){
			if ( p_packet->UDP_header.port_dst == 53 || p_packet->UDP_header.port_src == 53 ) return TRUE;
		} else if ( has_TCP_header( p_packet ) ){
			if ( p_packet->TCP_header.port_dst == 53 || p_packet->TCP_header.port_src == 53 ) return TRUE;
		} 
		
		return FALSE;
	} else{
		return FALSE;
	}
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
	
	// Add size of FCS (CRC32 checksum of ethernet)
	size += 4;

	p_packet->unique_ID = unique_ID++;
	p_packet->p_data = (u_char*) malloc( size + 4 );
	p_packet->size = size;
	p_packet->used = FALSE;

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

	// Add size of FCS (CRC32 checksum of ethernet)
	size += 4;

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

	PACKET *p_temp_packet = init_packet_uint8_t( p_packet->size - 4, get_data( p_packet ) );
	p_temp_packet->unique_ID = p_packet->unique_ID;
	p_temp_packet->used = FALSE;
	p_temp_packet->type = p_packet->type;

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

    printf("----PACKET (total size = %d, count = %d)----\n", p_packet->size, counter++ );

    char *p_text = get_packet_text( p_packet );
    if ( strlen( p_text ) > 0 ){
		printf("    MESSAGE: %s\n", get_packet_text( p_packet ) ); 
    }

    printf("  UNIQUE_ID: %d\n", get_unique_ID( p_packet ) ); 
	printf("       TYPE: %s\n", get_type_name( p_packet ) ); 


    if ( is_ethernet_packet( p_packet ) ){
    	print_ethernet_packet( p_packet );
    } else if ( is_radio_tap_packet( p_packet ) ){
    	print_radio_tap_packet( p_packet );
    } 
}

static void print_radio_tap_packet( PACKET* p_packet ){
	print_radio_tap_header( p_packet );
}

static void print_radio_tap_header( PACKET* p_packet ){
    if ( p_packet == NULL ) {
        print_warning( "packet.c: print_radio_tap_header() --> p_packet == NULL\n" );
        return;
    }	

    printf("  RADIO_TAP: length      --> %d\n", get_radio_tap_length( p_packet ) );
    printf("  RADIO_TAP: time        --> %llu\n", get_radio_tap_time( p_packet ) );
    printf("  RADIO_TAP: type        --> %s\n", get_radio_tap_type_name( p_packet ) );
    printf("  RADIO_TAP: to_DS       --> %d\n", get_radio_tap_to_DS( p_packet ) );
    printf("  RADIO_TAP: from_DS     --> %d\n", get_radio_tap_from_DS( p_packet ) );

	uint8_t type = get_radio_tap_type( p_packet );

	if ( type == TYPE_RADIO_TAP_BEACON ||  type == TYPE_RADIO_TAP_AUTHENTICATION || type == TYPE_RADIO_TAP_ASSOCIATION_REQUEST || 
		 type == TYPE_RADIO_TAP_ASSOCIATION_RESPONS || type == TYPE_RADIO_TAP_DATA || type == TYPE_RADIO_TAP_DISASSOCIATION ){

		uint8_t to_DS = get_radio_tap_to_DS( p_packet );
		uint8_t from_DS = get_radio_tap_from_DS( p_packet );


		if ( to_DS == 0 && from_DS == 0 ){
			printf("  RADIO_TAP: dst_address --> %s\n", get_MAC_address_name( get_radio_tap_dst_address( p_packet ) ) );
			printf("  RADIO_TAP: src_address --> %s\n", get_MAC_address_name( get_radio_tap_src_address( p_packet ) ) );
			printf("  RADIO_TAP: BSSID       --> %s\n", get_MAC_address_name( get_radio_tap_BSSID( p_packet ) ) );
		} else if ( to_DS == 0 && from_DS == 1 ){
			printf("  RADIO_TAP: dst_address --> %s\n", get_MAC_address_name( get_radio_tap_dst_address( p_packet ) ) );
			printf("  RADIO_TAP: BSSID       --> %s\n", get_MAC_address_name( get_radio_tap_BSSID( p_packet ) ) );
			printf("  RADIO_TAP: src_address --> %s\n", get_MAC_address_name( get_radio_tap_src_address( p_packet ) ) );
		} else if ( to_DS == 1 && from_DS == 0 ){
			printf("  RADIO_TAP: BSSID       --> %s\n", get_MAC_address_name( get_radio_tap_BSSID( p_packet ) ) );
			printf("  RADIO_TAP: src_address --> %s\n", get_MAC_address_name( get_radio_tap_src_address( p_packet ) ) );
			printf("  RADIO_TAP: dst_address --> %s\n", get_MAC_address_name( get_radio_tap_dst_address( p_packet ) ) );
		} else if ( to_DS == 1 && from_DS == 1 ){
			printf("  RADIO_TAP: receiving_station_address    --> %s\n", get_MAC_address_name( get_radio_tap_receiving_station_address( p_packet ) ) );
			printf("  RADIO_TAP: transmission_station_address --> %s\n", get_MAC_address_name( get_radio_tap_transmission_station_address( p_packet ) ) );
			printf("  RADIO_TAP: dst_address                  --> %s\n", get_MAC_address_name( get_radio_tap_dst_address( p_packet ) ) );
		}
	}

	printf("-----------------\n" ); 
	return;
}

static void print_ethernet_packet( PACKET* p_packet ){
    if ( p_packet == NULL ) {
        print_warning( "packet.c: print_ethernet_packet() --> p_packet == NULL\n" );
        return;
    }

    if ( p_packet->size == 0 ) {
        print_debug( "packet.c: print_ethernet_packet() --> p_packet->size == 0\n" );
        return;
    }

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







