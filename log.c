#include "log.h"

static LOCAL_MESSAGE_BUS *p_local_message_bus;

void init_log( void ){
	uint8_t ARP_notice = SUBSCRIBED;
	uint8_t ARP_error = SUBSCRIBED;

	p_local_message_bus = create_message_bus_subscription( ARP_notice, ARP_error );
}

void update_log( void ){
	PACKET *p_ARP_packets_error = get_ARP_error_from_message_bus( p_local_message_bus );
	PACKET *p_ARP_packets_notice = get_ARP_notice_from_message_bus( p_local_message_bus );

	if ( p_ARP_packets_error != NULL ){
		print_packet( p_ARP_packets_error );
		free_packet( p_ARP_packets_error );
	}

	if ( p_ARP_packets_notice != NULL ){
		print_packet( p_ARP_packets_notice );
		free_packet( p_ARP_packets_notice );
	}
}
