#include "message_bus.h"

static MESSAGE_BUS_SUBSCRIPTIONS* p_local_message_bus_subscriptions;

static MESSAGE_BUS_SUBSCRIPTIONS* malloc_message_bus_subsriptions( void );
static LOCAL_MESSAGE_BUS* malloc_message_bus_subsription( uint8_t ARP_notice, uint8_t ARP_error, uint8_t WIFI_radio_tap_notice, uint8_t WIFI_ARP_notice );
static uint32_t add_message_bus_subsription( MESSAGE_BUS_SUBSCRIPTION* p_local_message_bus );
static LOCAL_MESSAGE_BUS* malloc_local_message_bus( void );

void free_message_bus_subsription( MESSAGE_BUS_SUBSCRIPTION *p_message_bus_subscription ){
	if ( p_message_bus_subscription == NULL ){
		print_warning( "message_bus.c: free_message_bus_subsription --> p_message_bus_subscription == NULL\n" );
		return;
	}

	if ( p_message_bus_subscription->p_local_message_bus != NULL ){
		free_local_message_bus( p_message_bus_subscription->p_local_message_bus );
	}

	free( p_message_bus_subscription );
}

void free_local_message_bus( LOCAL_MESSAGE_BUS *p_local_message_bus ){
	if ( p_local_message_bus == NULL ){
		print_warning( "message_bus.c: free_message_bus_subsription --> p_local_message_bus == NULL\n" );
		return;
	}

	for ( int i = 0; i < MESSAGE_BUS_MAX_NUMBER_OF_ARP_PACKETS_NOTICE; i++ ){
		PACKET *p_packet = p_local_message_bus->p_ARP_packets_notice[i];

		if ( p_packet != NULL ){
			free_packet( p_packet );
		}
	}

	for ( int i = 0; i < MESSAGE_BUS_MAX_NUMBER_OF_ARP_PACKETS_ERROR; i++ ){
		PACKET *p_packet = p_local_message_bus->p_ARP_packets_error[i];

		if ( p_packet != NULL ){
			free_packet( p_packet );
		}
	}

	for ( int i = 0; i < MESSAGE_BUS_MAX_NUMBER_OF_WIFI_RADIO_TAP_PACKETS_NOTICE; i++ ){
		PACKET *p_packet = p_local_message_bus->p_WIFI_radio_tap_packets_notice[i];

		if ( p_packet != NULL ){
			free_packet( p_packet );
		}
	}

	for ( int i = 0; i < MESSAGE_BUS_MAX_NUMBER_OF_WIFI_ARP_PACKETS_NOTICE; i++ ){
		PACKET *p_packet = p_local_message_bus->p_WIFI_ARP_packets_notice[i];

		if ( p_packet != NULL ){
			free_packet( p_packet );
		}
	}

	free( p_local_message_bus );
	return;
}

void init_message_bus( void ){
	p_local_message_bus_subscriptions = malloc_message_bus_subsriptions();

	if ( p_local_message_bus_subscriptions == NULL ){
		print_warning( "message_bus.c: init_message_bus() --> p_local_message_bus_subscriptions == NULL\n" );
		return;
	}
}

static MESSAGE_BUS_SUBSCRIPTIONS* malloc_message_bus_subsriptions(){
	MESSAGE_BUS_SUBSCRIPTIONS* p_message_bus_subscriptions = (MESSAGE_BUS_SUBSCRIPTIONS*) malloc( sizeof( MESSAGE_BUS_SUBSCRIPTIONS ) );

	p_message_bus_subscriptions->number_of_message_bus_subsciptions = 0;

	for ( int i = 0; i < MESSAGE_BUS_MAX_NUMBER_OF_MESSAGE_BUS_SUBSRIPTIONS; i++ ){
		p_message_bus_subscriptions->p_message_bus_subscriptions[i] = NULL;
	}

	if ( p_message_bus_subscriptions == NULL ){
		print_warning( "message_bus.c: malloc_message_bus_subsriptions() --> p_message_bus_subscriptions == NULL\n" );
		return NULL;
	}

	return p_message_bus_subscriptions;
}

static LOCAL_MESSAGE_BUS* malloc_message_bus_subsription( uint8_t ARP_notice, uint8_t ARP_error, uint8_t WIFI_radio_tap_notice, uint8_t WIFI_ARP_notice ){
	MESSAGE_BUS_SUBSCRIPTION* p_message_bus_subscription = (MESSAGE_BUS_SUBSCRIPTION*) malloc( sizeof( MESSAGE_BUS_SUBSCRIPTION ) );

	p_message_bus_subscription->ARP_notice = ARP_notice;
	p_message_bus_subscription->ARP_error = ARP_error;
	p_message_bus_subscription->WIFI_radio_tap_notice = WIFI_radio_tap_notice;
	p_message_bus_subscription->WIFI_ARP_notice = WIFI_ARP_notice;

	LOCAL_MESSAGE_BUS *p_local_message_bus = malloc_local_message_bus();

	p_message_bus_subscription->p_local_message_bus = p_local_message_bus;

	uint32_t status = add_message_bus_subsription( p_message_bus_subscription );

	if ( !status ){
		free_message_bus_subsription( p_message_bus_subscription );
		return NULL;
	}

	return p_local_message_bus;
}

static uint32_t add_message_bus_subsription( MESSAGE_BUS_SUBSCRIPTION* p_local_message_bus_subsription ){
	if ( p_local_message_bus_subsription == NULL ){
		print_warning( "message_bus.c: add_message_bus_subsription() --> p_local_message_bus_subsription == NULL\n" );
		return FALSE;
	}

	if ( p_local_message_bus_subscriptions == NULL ){
		print_warning( "message_bus.c: add_message_bus_subsription() --> p_local_message_bus_subscriptions == NULL\n" );
		return FALSE;
	}

	uint32_t number_of_message_bus_subsciptions = p_local_message_bus_subscriptions->number_of_message_bus_subsciptions;

	if ( number_of_message_bus_subsciptions >= MESSAGE_BUS_MAX_NUMBER_OF_MESSAGE_BUS_SUBSRIPTIONS ){
		print_warning( "message_bus.c: add_message_bus_subsription() --> number_of_message_bus_subsciptions >= MESSAGE_BUS_MAX_NUMBER_OF_MESSAGE_BUS_SUBSRIPTIONS\n" );
		return FALSE;
	}

	for ( int i = 0; i < MESSAGE_BUS_MAX_NUMBER_OF_MESSAGE_BUS_SUBSRIPTIONS; i++ ){
		MESSAGE_BUS_SUBSCRIPTION *p_temp_message_bus_subscription = p_local_message_bus_subscriptions->p_message_bus_subscriptions[i];

		if ( p_local_message_bus_subscriptions->p_message_bus_subscriptions[i] == NULL ){
			p_local_message_bus_subscriptions->p_message_bus_subscriptions[i] = p_local_message_bus_subsription;
			p_local_message_bus_subscriptions->number_of_message_bus_subsciptions += 1;
			return TRUE;
		}
	}

	return FALSE;
}

static LOCAL_MESSAGE_BUS* malloc_local_message_bus(){
	LOCAL_MESSAGE_BUS* p_local_message_bus = (LOCAL_MESSAGE_BUS*) malloc( sizeof( LOCAL_MESSAGE_BUS ) );

	p_local_message_bus->number_of_ARP_packets_notice = 0;
	p_local_message_bus->number_of_ARP_packets_error = 0;
	p_local_message_bus->number_of_WIFI_radio_tap_packets_notice = 0;
	p_local_message_bus->number_of_WIFI_ARP_packets_notice = 0;

	for ( int i = 0; i < MESSAGE_BUS_MAX_NUMBER_OF_ARP_PACKETS_NOTICE; i++ ){
		p_local_message_bus->p_ARP_packets_notice[i] = NULL;
	}

	for ( int i = 0; i < MESSAGE_BUS_MAX_NUMBER_OF_ARP_PACKETS_ERROR; i++ ){
		p_local_message_bus->p_ARP_packets_error[i] = NULL;
	}

	for ( int i = 0; i < MESSAGE_BUS_MAX_NUMBER_OF_WIFI_RADIO_TAP_PACKETS_NOTICE; i++ ){
		p_local_message_bus->p_WIFI_radio_tap_packets_notice[i] = NULL;
	}

	for ( int i = 0; i < MESSAGE_BUS_MAX_NUMBER_OF_WIFI_ARP_PACKETS_NOTICE; i++ ){
		p_local_message_bus->p_WIFI_ARP_packets_notice[i] = NULL;
	}

	return p_local_message_bus;
}

LOCAL_MESSAGE_BUS* create_message_bus_subscription( uint8_t ARP_notice, uint8_t ARP_error, uint8_t WIFI_radio_tap_notice, uint8_t WIFI_ARP_notice ){
	return malloc_message_bus_subsription( ARP_notice, ARP_error, WIFI_radio_tap_notice, WIFI_ARP_notice );
}

PACKET* get_ARP_notice_from_message_bus( LOCAL_MESSAGE_BUS *p_local_message_bus ){
	if ( p_local_message_bus == NULL ){
		print_warning( "message_bus.c: get_ARP_notice_from_message_bus() --> p_local_message_bus == NULL\n" );
		return NULL;
	}

	uint32_t number_of_ARP_packets_notice = p_local_message_bus->number_of_ARP_packets_notice;

	if ( number_of_ARP_packets_notice > 0 ){
		for ( int i = 0; i < MESSAGE_BUS_MAX_NUMBER_OF_ARP_PACKETS_NOTICE; i++ ){
			PACKET *p_packet = p_local_message_bus->p_ARP_packets_notice[i];

			if ( p_packet != NULL ){
				p_local_message_bus->number_of_ARP_packets_notice -= 1;
				p_local_message_bus->p_ARP_packets_notice[i] = NULL;
				return p_packet;
			}
		}

		return NULL;
	} else{
		return NULL;
	}
}

PACKET* get_ARP_error_from_message_bus( LOCAL_MESSAGE_BUS *p_local_message_bus ){
	if ( p_local_message_bus == NULL ){
		print_warning( "message_bus.c: get_ARP_error_from_message_bus() --> p_local_message_bus == NULL\n" );
		return NULL;
	}

	uint32_t number_of_ARP_packets_error = p_local_message_bus->number_of_ARP_packets_error;

	if ( number_of_ARP_packets_error > 0 ){
		for ( int i = 0; i < MESSAGE_BUS_MAX_NUMBER_OF_ARP_PACKETS_ERROR; i++ ){
			PACKET *p_packet = p_local_message_bus->p_ARP_packets_error[i];

			if ( p_local_message_bus->p_ARP_packets_error[i] != NULL ){
				p_local_message_bus->number_of_ARP_packets_error -= 1;
				p_local_message_bus->p_ARP_packets_error[i] = NULL;
				return p_packet;
			}
		}

		return NULL;
	} else{
		return NULL;
	}
}


PACKET* get_WIFI_radio_tap_notice_from_message_bus( LOCAL_MESSAGE_BUS *p_local_message_bus ){
	if ( p_local_message_bus == NULL ){
		print_warning( "message_bus.c: get_WIFI_radio_tap_notice_from_message_bus() --> p_local_message_bus == NULL\n" );
		return NULL;
	}

	uint32_t number_of_WIFI_radio_tap_packets_notice = p_local_message_bus->number_of_WIFI_radio_tap_packets_notice;

	if ( number_of_WIFI_radio_tap_packets_notice > 0 ){
		for ( int i = 0; i < MESSAGE_BUS_MAX_NUMBER_OF_WIFI_RADIO_TAP_PACKETS_NOTICE; i++ ){
			PACKET *p_packet = p_local_message_bus->p_WIFI_radio_tap_packets_notice[i];

			if ( p_local_message_bus->p_WIFI_radio_tap_packets_notice[i] != NULL ){
				p_local_message_bus->number_of_WIFI_radio_tap_packets_notice -= 1;
				p_local_message_bus->p_WIFI_radio_tap_packets_notice[i] = NULL;
				return p_packet;
			}
		}

		return NULL;
	} else{
		return NULL;
	}
}


PACKET* get_WIFI_ARP_notice_from_message_bus( LOCAL_MESSAGE_BUS *p_local_message_bus ){
	if ( p_local_message_bus == NULL ){
		print_warning( "message_bus.c: get_WIFI_ARP_notice_from_message_bus() --> p_local_message_bus == NULL\n" );
		return NULL;
	}

	uint32_t number_of_WIFI_ARP_packets_notice = p_local_message_bus->number_of_WIFI_ARP_packets_notice;

	if ( number_of_WIFI_ARP_packets_notice > 0 ){
		for ( int i = 0; i < MESSAGE_BUS_MAX_NUMBER_OF_WIFI_ARP_PACKETS_NOTICE; i++ ){
			PACKET *p_packet = p_local_message_bus->p_WIFI_ARP_packets_notice[i];

			if ( p_local_message_bus->p_WIFI_ARP_packets_notice[i] != NULL ){
				p_local_message_bus->number_of_WIFI_ARP_packets_notice -= 1;
				p_local_message_bus->p_WIFI_ARP_packets_notice[i] = NULL;
				return p_packet;
			}
		}

		return NULL;
	} else{
		return NULL;
	}
}

static void add_ARP_notice_to_local_message_bus( LOCAL_MESSAGE_BUS *p_local_message_bus, PACKET *p_packet ){
	if ( p_local_message_bus == NULL ){
		print_warning( "message_bus.c: add_ARP_notice_to_local_message_bus() --> p_local_message_bus == NULL\n" );
		return;
	}

	uint32_t number_of_ARP_packets_notice = p_local_message_bus->number_of_ARP_packets_notice;

	if ( number_of_ARP_packets_notice >= MESSAGE_BUS_MAX_NUMBER_OF_ARP_PACKETS_NOTICE ){
		print_warning( "message_bus.c: add_ARP_notice_to_local_message_bus() --> number_of_ARP_packets_notice >= MESSAGE_BUS_MAX_NUMBER_OF_ARP_PACKETS_NOTICE\n" );
		return;
	}

	if ( is_ethernet_packet( p_packet ) == FALSE ){
		print_warning( "message_bus.c: add_ARP_notice_to_local_message_bus() --> is_ethernet_packet( p_packet ) == FALSE\n" );
		return;
	}

	PACKET *p_temp_packet = clone_packet( p_packet );
	parse_packet( p_temp_packet, TYPE_ETHERNET );

	for ( int i = 0; i < MESSAGE_BUS_MAX_NUMBER_OF_ARP_PACKETS_NOTICE; i++ ){
		if ( p_local_message_bus->p_ARP_packets_notice[i] == NULL ){
			p_local_message_bus->p_ARP_packets_notice[i] = p_temp_packet;
			p_local_message_bus->number_of_ARP_packets_notice += 1;
			return;
		}
	}

	return;
}

void send_ARP_notice_to_message_bus( PACKET *p_ARP_packet_notice ){
	if ( p_ARP_packet_notice == NULL ){
		print_warning( "message_bus.c: send_ARP_notice_to_message_bus() --> p_ARP_packet_notice == NULL\n" );
		return;
	}

	if ( p_local_message_bus_subscriptions == NULL ){
		print_warning( "message_bus.c: send_ARP_notice_to_message_bus() --> p_local_message_bus_subscriptions == NULL\n" );
		return;
	}

	for ( int i = 0; i < MESSAGE_BUS_MAX_NUMBER_OF_MESSAGE_BUS_SUBSRIPTIONS; i++ ){
		MESSAGE_BUS_SUBSCRIPTION *p_message_bus_subscription = p_local_message_bus_subscriptions->p_message_bus_subscriptions[i];

		if ( p_message_bus_subscription != NULL ){
			LOCAL_MESSAGE_BUS *p_local_message_bus = p_message_bus_subscription->p_local_message_bus;

			if ( p_message_bus_subscription->ARP_notice == SUBSCRIBED ){
				add_ARP_notice_to_local_message_bus( p_local_message_bus, p_ARP_packet_notice );
			}
		}
	}
}


static void add_ARP_error_to_local_message_bus( LOCAL_MESSAGE_BUS *p_local_message_bus, PACKET *p_packet ){
	if ( p_local_message_bus == NULL ){
		print_warning( "message_bus.c: add_ARP_error_to_local_message_bus() --> p_local_message_bus == NULL\n" );
		return;
	}

	uint32_t number_of_ARP_packets_error = p_local_message_bus->number_of_ARP_packets_error;

	if ( number_of_ARP_packets_error >= MESSAGE_BUS_MAX_NUMBER_OF_ARP_PACKETS_ERROR ){
		print_warning( "message_bus.c: add_ARP_error_to_local_message_bus() --> number_of_ARP_packets_error >= MESSAGE_BUS_MAX_NUMBER_OF_ARP_PACKETS_ERROR\n" );
		return;
	}

	if ( is_ethernet_packet( p_packet ) == FALSE ){
		print_warning( "message_bus.c: add_ARP_error_to_local_message_bus() --> is_ethernet_packet( p_packet ) == FALSE\n" );
		return;
	}

	PACKET *p_clone_packet = clone_packet( p_packet );
	parse_packet( p_clone_packet, TYPE_ETHERNET );

	for ( int i = 0; i < MESSAGE_BUS_MAX_NUMBER_OF_ARP_PACKETS_ERROR; i++ ){
		if ( p_local_message_bus->p_ARP_packets_error[i] == NULL ){
			p_local_message_bus->p_ARP_packets_error[i] = p_clone_packet;
			p_local_message_bus->number_of_ARP_packets_error += 1;
			return;
		}
	}

	return;
}

void send_ARP_error_to_message_bus( PACKET *p_ARP_packet_error ){
	if ( p_ARP_packet_error == NULL ){
		print_warning( "message_bus.c: send_ARP_error_to_message_bus() --> p_ARP_packet_error == NULL\n" );
		return;
	}

	if ( p_local_message_bus_subscriptions == NULL ){
		print_warning( "message_bus.c: send_ARP_error_to_message_bus() --> p_local_message_bus_subscriptions == NULL\n" );
		return;
	}

	for ( int i = 0; i < MESSAGE_BUS_MAX_NUMBER_OF_MESSAGE_BUS_SUBSRIPTIONS; i++ ){

		MESSAGE_BUS_SUBSCRIPTION *p_message_bus_subscription = p_local_message_bus_subscriptions->p_message_bus_subscriptions[i];

		if ( p_message_bus_subscription != NULL ){
			LOCAL_MESSAGE_BUS *p_local_message_bus = p_message_bus_subscription->p_local_message_bus;

			if ( p_message_bus_subscription->ARP_error == SUBSCRIBED ){
				add_ARP_error_to_local_message_bus( p_local_message_bus, p_ARP_packet_error );
			}
		}
	}
}

static void add_WIFI_radio_tap_notice_to_local_message_bus( LOCAL_MESSAGE_BUS *p_local_message_bus, PACKET *p_WIFI_radio_tap_packet_notice ){
	if ( p_local_message_bus == NULL ){
		print_warning( "message_bus.c: add_ARP_error_to_local_message_bus() --> p_local_message_bus == NULL\n" );
		return;
	}

	uint32_t number_of_WIFI_radio_tap_packets_notice = p_local_message_bus->number_of_WIFI_radio_tap_packets_notice;

	if ( number_of_WIFI_radio_tap_packets_notice >= MESSAGE_BUS_MAX_NUMBER_OF_WIFI_RADIO_TAP_PACKETS_NOTICE ){
		print_warning( "message_bus.c: add_ARP_error_to_local_message_bus() --> number_of_WIFI_radio_tap_packets_notice >= MESSAGE_BUS_MAX_NUMBER_OF_WIFI_RADIO_TAP_PACKETS_NOTICE\n" );
		return;
	}

	if ( is_radio_tap_packet( p_WIFI_radio_tap_packet_notice ) == FALSE ){
		print_warning( "message_bus.c: add_ARP_error_to_local_message_bus() --> is_radio_tap_packet( p_WIFI_radio_tap_packet_notice ) == FALSE\n" );
		return;
	}

	PACKET *p_clone_packet = clone_packet( p_WIFI_radio_tap_packet_notice );
	parse_packet( p_clone_packet, TYPE_RADIO_TAP );

	for ( int i = 0; i < MESSAGE_BUS_MAX_NUMBER_OF_WIFI_RADIO_TAP_PACKETS_NOTICE; i++ ){
		if ( p_local_message_bus->p_WIFI_radio_tap_packets_notice[i] == NULL ){
			p_local_message_bus->p_WIFI_radio_tap_packets_notice[i] = p_clone_packet;
			p_local_message_bus->number_of_WIFI_radio_tap_packets_notice += 1;
			return;
		}
	}

	return;
}

void send_WIFI_radio_tap_notice_to_message_bus( PACKET *p_WIFI_radio_tap_packet_notice ){
	if ( p_WIFI_radio_tap_packet_notice == NULL ){
		print_warning( "message_bus.c: send_WIFI_radio_tap_notice_to_message_bus() --> p_WIFI_radio_tap_packet_notice == NULL\n" );
		return;
	}

	if ( p_local_message_bus_subscriptions == NULL ){
		print_warning( "message_bus.c: send_WIFI_radio_tap_notice_to_message_bus() --> p_local_message_bus_subscriptions == NULL\n" );
		return;
	}

	for ( int i = 0; i < MESSAGE_BUS_MAX_NUMBER_OF_MESSAGE_BUS_SUBSRIPTIONS; i++ ){

		MESSAGE_BUS_SUBSCRIPTION *p_message_bus_subscription = p_local_message_bus_subscriptions->p_message_bus_subscriptions[i];

		if ( p_message_bus_subscription != NULL ){
			LOCAL_MESSAGE_BUS *p_local_message_bus = p_message_bus_subscription->p_local_message_bus;

			if ( p_message_bus_subscription->WIFI_radio_tap_notice == SUBSCRIBED ){
				add_WIFI_radio_tap_notice_to_local_message_bus( p_local_message_bus, p_WIFI_radio_tap_packet_notice );
			}
		}
	}
}

static void add_WIFI_ARP_notice_to_local_message_bus( LOCAL_MESSAGE_BUS *p_local_message_bus, PACKET *p_WIFI_ARP_packet_notice ){
	if ( p_local_message_bus == NULL ){
		print_warning( "message_bus.c: add_WIFI_ARP_notice_to_local_message_bus() --> p_local_message_bus == NULL\n" );
		return;
	}

	uint32_t number_of_WIFI_ARP_packets_notice = p_local_message_bus->number_of_WIFI_ARP_packets_notice;

	if ( number_of_WIFI_ARP_packets_notice >= MESSAGE_BUS_MAX_NUMBER_OF_WIFI_ARP_PACKETS_NOTICE ){
		print_warning( "message_bus.c: add_WIFI_ARP_notice_to_local_message_bus() --> number_of_WIFI_ARP_packets_notice >= MESSAGE_BUS_MAX_NUMBER_OF_WIFI_ARP_PACKETS_NOTICE\n" );
		return;
	}

	if ( is_radio_tap_packet( p_WIFI_ARP_packet_notice ) == FALSE ){
		print_warning( "message_bus.c: add_WIFI_ARP_notice_to_local_message_bus() --> is_radio_tap_packet( p_WIFI_ARP_packet_notice ) == FALSE\n" );
		return;
	}

	PACKET *p_clone_packet = clone_packet( p_WIFI_ARP_packet_notice );
	parse_packet( p_clone_packet, TYPE_RADIO_TAP );

	for ( int i = 0; i < MESSAGE_BUS_MAX_NUMBER_OF_WIFI_ARP_PACKETS_NOTICE; i++ ){
		if ( p_local_message_bus->p_WIFI_ARP_packets_notice[i] == NULL ){
			p_local_message_bus->p_WIFI_ARP_packets_notice[i] = p_clone_packet;
			p_local_message_bus->number_of_WIFI_ARP_packets_notice += 1;
			return;
		}
	}

	return;
}

void send_WIFI_ARP_notice_to_message_bus( PACKET *p_WIFI_ARP_packet_notice ){
	if ( p_WIFI_ARP_packet_notice == NULL ){
		print_warning( "message_bus.c: send_WIFI_radio_tap_notice_to_message_bus() --> p_WIFI_ARP_packet_notice == NULL\n" );
		return;
	}

	if ( p_local_message_bus_subscriptions == NULL ){
		print_warning( "message_bus.c: send_WIFI_radio_tap_notice_to_message_bus() --> p_local_message_bus_subscriptions == NULL\n" );
		return;
	}

	for ( int i = 0; i < MESSAGE_BUS_MAX_NUMBER_OF_MESSAGE_BUS_SUBSRIPTIONS; i++ ){

		MESSAGE_BUS_SUBSCRIPTION *p_message_bus_subscription = p_local_message_bus_subscriptions->p_message_bus_subscriptions[i];

		if ( p_message_bus_subscription != NULL ){
			LOCAL_MESSAGE_BUS *p_local_message_bus = p_message_bus_subscription->p_local_message_bus;

			if ( p_message_bus_subscription->WIFI_radio_tap_notice == SUBSCRIBED ){
				add_WIFI_ARP_notice_to_local_message_bus( p_local_message_bus, p_WIFI_ARP_packet_notice );
			}
		}
	}
}





