#include "log.h"

static LOCAL_MESSAGE_BUS *p_local_message_bus;

void init_log( void ){
	uint8_t ARP_notice = SUBSCRIBED;
	uint8_t ARP_error = SUBSCRIBED;
	uint8_t WIFI_radio_tap_notice = SUBSCRIBED;
	uint8_t WIFI_ARP_notice = SUBSCRIBED;

	p_local_message_bus = create_message_bus_subscription( ARP_notice, ARP_error, WIFI_radio_tap_notice, WIFI_ARP_notice );
}

void update_log( void ){
	PACKET *p_ARP_packet_error = get_ARP_error_from_message_bus( p_local_message_bus );
	PACKET *p_ARP_packet_notice = get_ARP_notice_from_message_bus( p_local_message_bus );
	PACKET *p_WIFI_radio_tap_packet_notice = get_WIFI_radio_tap_notice_from_message_bus( p_local_message_bus );
	PACKET *p_WIFI_ARP_packet_notice = get_WIFI_ARP_notice_from_message_bus( p_local_message_bus );

	if ( p_ARP_packet_error != NULL ){
		print_info( "log.c: p_ARP_packet_error\n" );
		print_packet( p_ARP_packet_error );
		free_packet( p_ARP_packet_error );
	}

	if ( p_ARP_packet_notice != NULL ){
		print_info( "log.c: p_ARP_packet_notice\n" );
		print_packet( p_ARP_packet_notice );
		free_packet( p_ARP_packet_notice );
	}

	if ( p_WIFI_radio_tap_packet_notice != NULL ){
		print_info( "log.c: p_WIFI_radio_tap_packet_notice\n" );
		print_packet( p_WIFI_radio_tap_packet_notice );
		free_packet( p_WIFI_radio_tap_packet_notice );
	}

	if ( p_WIFI_ARP_packet_notice != NULL ){
		print_info( "log.c: p_WIFI_ARP_packet_notice\n" );
		print_packet( p_WIFI_ARP_packet_notice );
		free_packet( p_WIFI_ARP_packet_notice );
	}
}
