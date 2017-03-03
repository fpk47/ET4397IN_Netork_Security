#include "packet.h"
#include "message.h"

uint32_t get_ethernet_header_size(){ return 14; }
uint32_t get_ip_4_header_size( IP_4_HEADER *p_ip_4_header ){ return ( p_ip_4_header->IHL ) * 4; }
uint32_t get_udp_header_size(){ return 8; }
uint32_t get_tcp_header_size( TCP_HEADER *p_tcp_header ){ return ( p_tcp_header->data_offset ) * 4; }
uint32_t get_dns_header_size(){ return 12; }

uint16_t get_ethernet_type( PACKET* p_packet ){ return p_packet->ethernet_header.type; }
uint32_t get_dns_number_of_queries( PACKET* p_packet ){ return p_packet->dns_header.query_count; }
uint32_t get_dns_number_of_answers( PACKET* p_packet ){ return p_packet->dns_header.answer_count; }
uint32_t get_dns_number_of_authorities( PACKET* p_packet ){ return p_packet->dns_header.authority_count; }
uint32_t get_dns_number_of_additionals( PACKET* p_packet ){ return p_packet->dns_header.additional_count; }

ETHERNET_HEADER* get_ethernet_header( PACKET *p_packet ){ return (ETHERNET_HEADER*) &(p_packet->ethernet_header); }
IP_4_HEADER* get_IP_4_header( PACKET *p_packet ){ return (IP_4_HEADER*) &(p_packet->ip_4_header); }
UDP_HEADER* get_UDP_header( PACKET *p_packet ){ return (UDP_HEADER*) &(p_packet->udp_header); }
TCP_HEADER* get_TCP_header( PACKET *p_packet ){ return (TCP_HEADER*) &(p_packet->tcp_header); }
DNS_HEADER* get_DNS_header( PACKET *p_packet ){ return (DNS_HEADER*) &(p_packet->dns_header); }
RR_QUERY_ENTRY* get_rr_query_entry( PACKET *p_packet ){ return  (RR_QUERY_ENTRY*) &(p_packet->rr_query_entry); }

uint8_t is_udp_packet( PACKET *p_packet ){
	if ( p_packet->ip_4_header.protocol == TYPE_UDP ){
		return TRUE;
	} else{
		return FALSE;
	}
}

uint8_t is_tcp_packet( PACKET *p_packet ){
	if ( p_packet->ip_4_header.protocol == TYPE_TCP ){
		return TRUE;
	} else{
		return FALSE;
	}
}

uint8_t is_dns_packet( PACKET *p_packet ){
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
	free( p_packet->p_data );
	free( p_packet );
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
    printf("   ETHERNET: mac_dst     --> %02x:%02x:%02x:%02x:%02x:%02x\n", p_mac_dst[0], p_mac_dst[1], p_mac_dst[2], p_mac_dst[3], p_mac_dst[4], p_mac_dst[5] );
    printf("   ETHERNET: mac_src     --> %02x:%02x:%02x:%02x:%02x:%02x\n", p_mac_src[0], p_mac_src[1], p_mac_src[2], p_mac_src[3], p_mac_src[4], p_mac_src[5] );
	printf("   ETHERNET: size        --> %d\n", get_ethernet_header_size() ); 

    if ( get_ethernet_type( p_packet ) == TYPE_IP4 ) { printf("   ETHERNET: type        --> IP4\n" ); }
    else									   				  { printf("   ETHERNET: type        --> %04x [NOT IP4, ABORTING]\n", p_ethernet_header->type ); printf("-----------------\n" ); return; }

	IP_4_HEADER *p_ip_4_header = &(p_packet->ip_4_header);
	uint8_t *p_ip_4_dst = p_ip_4_header->ip_4_dst;
	uint8_t *p_ip_4_src = p_ip_4_header->ip_4_src;

    printf("        IP4: ip4_dst     --> %d.%d.%d.%d\n", p_ip_4_dst[0], p_ip_4_dst[1], p_ip_4_dst[2], p_ip_4_dst[3] );
    printf("        IP4: ip4_src     --> %d.%d.%d.%d\n", p_ip_4_src[0], p_ip_4_src[1], p_ip_4_src[2], p_ip_4_src[3] );
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

    if ( get_dns_number_of_queries( p_packet ) == 1 ){
    	RR_QUERY_ENTRY *p_rr_query_entry = get_rr_query_entry( p_packet );
    	printf( "%s %04x %04x\n", p_rr_query_entry->name, p_rr_query_entry->rr_type, p_rr_query_entry->rr_class );
    }

    printf("-----------------\n" );
}