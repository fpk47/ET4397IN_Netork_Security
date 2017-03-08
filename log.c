#include "log.h"

static LOCAL_MESSAGE_BUS *p_local_message_bus;

void init_log( void ){
	uint8_t arp_notice = SUBSCRIBED;
	uint8_t arp_error = SUBSCRIBED;

	p_local_message_bus = create_message_bus_subscription( arp_notice, arp_error );
}

void update_log( void ){
	
}
