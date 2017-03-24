#include "wifi.h"

static LOCAL_MESSAGE_BUS *p_local_message_bus;

static char text[200];

#define LIST_SIZE 50
static PACKET *p_packets[ LIST_SIZE ];
static uint32_t oldest_index;
static uint32_t current_index;

static void init_list( void );
static uint32_t get_oldest_index_from_list( void );
static void add_packet_to_list( PACKET *p_packet );
static PACKET* get_packet_from_list( uint32_t index );

static void increase_index( uint32_t *p_index ){
	(*p_index)++;

	if ( *p_index > LIST_SIZE - 1 ){
		*p_index = 0;
	}
}

static void decrease_index( uint32_t *p_index ){
	if ( *p_index == 0 ){
		*p_index = LIST_SIZE - 1;
	} else{
		(*p_index)--;
	}
}

static void init_list( void ){
	for ( int i = 0; i < LIST_SIZE; i++ ){
		p_packets[i] = NULL;
	}

	oldest_index = 1;
	current_index = 0;
}

static uint32_t get_current_index_from_list( void ){
	uint32_t temp = current_index;
	return temp;
}

static uint32_t get_oldest_index_from_list( void ){
	uint32_t temp = oldest_index;
	return temp;
}

static void add_packet_to_list( PACKET *p_packet ){
	if ( p_packet == NULL ){
		print_warning( "wifi.c: add_packet_to_list() --> p_packet == NULL\n" );
		return;
	}

	increase_index( &current_index );

	PACKET *p_temp_packet = get_packet_from_list( current_index );

	if ( p_temp_packet != NULL ){
		increase_index( &oldest_index );
		free_packet( p_temp_packet );
	}

	PACKET *p_clone_packet = clone_packet( p_packet );
	parse_packet( p_clone_packet, get_type( p_clone_packet ) );

	p_packets[ current_index ] = p_clone_packet;

}

static PACKET* get_packet_from_list( uint32_t index ){
	if ( index > LIST_SIZE ){
		print_warning( "wifi.c: add_packet_to_list() --> index > LIST_SIZE\n" );
		return NULL;
	}

	return p_packets[ index ];
}

void init_WIFI( void ){
	init_list();

	uint8_t ARP_notice = UNSUBSCRIBED;
	uint8_t ARP_error = UNSUBSCRIBED;
	uint8_t WIFI_radio_tap_notice = UNSUBSCRIBED;
	uint8_t WIFI_ARP_notice = UNSUBSCRIBED;

	p_local_message_bus = create_message_bus_subscription( ARP_notice, ARP_error, WIFI_radio_tap_notice, WIFI_ARP_notice );

}


static PACKET* get_next_data_packet( uint32_t *p_index, uint32_t limit ){
	for ( uint32_t i = *p_index; i != limit; increase_index( &i ) ){
		PACKET *p_temp_packet = get_packet_from_list( i );

		if ( p_temp_packet != NULL && get_radio_tap_type( p_temp_packet ) == TYPE_RADIO_TAP_DATA ){
			return p_temp_packet;
		}

		increase_index( p_index );
	}
	return NULL;
}

static void detect_short_time_between_data_frames(){
	uint32_t limit = get_oldest_index_from_list();
	decrease_index( &limit );

	for ( uint32_t i = get_oldest_index_from_list(); i != limit; increase_index( &i ) ){
		uint32_t current_index = i;
		PACKET *p_current_data_packet = get_next_data_packet( &current_index, limit );

		uint32_t next_index = current_index;
		increase_index( &next_index );
		PACKET *p_next_data_packet = get_next_data_packet( &next_index, limit );

		if ( p_current_data_packet != NULL && p_next_data_packet != NULL && is_used( p_current_data_packet ) == FALSE ){
			set_used( p_current_data_packet );
			uint8_t type_1 = get_radio_tap_type( p_current_data_packet );
			uint8_t type_2 = get_radio_tap_type( p_next_data_packet );

			if ( type_1 == TYPE_RADIO_TAP_DATA && type_2 == TYPE_RADIO_TAP_DATA ){
				uint64_t time_current = get_radio_tap_time( p_current_data_packet );
				uint64_t time_next = get_radio_tap_time( p_next_data_packet );

				uint8_t *p_MAC_1;
				uint8_t *p_MAC_2;

				if ( has_radio_tap_src_address( p_current_data_packet ) ){ 
					p_MAC_1 = get_radio_tap_src_address( p_current_data_packet ); 
				}	

				if ( has_radio_tap_transmission_station_address( p_current_data_packet ) ){ 
					p_MAC_1 = get_radio_tap_transmission_station_address( p_current_data_packet ); 
				}	

				if ( has_radio_tap_src_address( p_next_data_packet ) ){ 
					p_MAC_2 = get_radio_tap_src_address( p_next_data_packet ); 
				}	

				if ( has_radio_tap_transmission_station_address( p_next_data_packet ) ){
					p_MAC_2 = get_radio_tap_transmission_station_address( p_next_data_packet ); 
				}	

				if ( compare_MAC( p_MAC_1, get_MAC_broadcast() ) == FALSE ){
					if ( compare_MAC( p_MAC_1, p_MAC_2 ) ){
						uint64_t diff = (time_next - time_current) / 1000;
	
						if ( diff < 50 ){
							sprintf( text, "WIFI ARP REPLAY NOTICE: %llums between data frame and data frame of %s", diff, get_MAC_address_name( p_MAC_1 ) );
							set_packet_text( p_current_data_packet, text );
							set_packet_text( p_next_data_packet, text );
							send_WIFI_ARP_notice_to_message_bus( p_current_data_packet );
							send_WIFI_ARP_notice_to_message_bus( p_next_data_packet );
						}
					}
				}
			}
		}
	}

	return;
}


static PACKET* find_client_authentication(){
	for( int i = 0; i < LIST_SIZE; i++ ){
		PACKET *p_temp_packet = get_packet_from_list( i );

		if ( p_temp_packet != NULL ){
			if ( is_radio_tap_packet( p_temp_packet ) ){
				if ( get_radio_tap_type( p_temp_packet ) == TYPE_RADIO_TAP_AUTHENTICATION ){

					uint8_t to_DS = get_radio_tap_to_DS( p_temp_packet );
					uint8_t from_DS = get_radio_tap_from_DS( p_temp_packet );

					if ( !(to_DS == 1 && from_DS == 1) ){
						uint8_t *p_MAC = get_radio_tap_src_address( p_temp_packet );
						uint8_t *p_BSSID = get_radio_tap_BSSID( p_temp_packet );
						
						// If p_BSSID != p_MAC --> Must be from client
						if ( !compare_MAC( p_MAC, p_BSSID ) && !is_used( p_temp_packet ) ){
							// Set used, to prevent using the same packet in the future..
							set_used( p_temp_packet );
							return p_temp_packet;
						}
					}
				}
			}
		}
	}

	return NULL;
} 

static PACKET* find_AP_disassociation(){
	for( int i = 0; i < LIST_SIZE; i++ ){
		PACKET *p_temp_packet = get_packet_from_list( i );

		if ( p_temp_packet != NULL ){
			if ( is_radio_tap_packet( p_temp_packet ) ){
				if ( get_radio_tap_type( p_temp_packet ) == TYPE_RADIO_TAP_DISASSOCIATION ){

					uint8_t to_DS = get_radio_tap_to_DS( p_temp_packet );
					uint8_t from_DS = get_radio_tap_from_DS( p_temp_packet );

					if ( !(to_DS == 1 && from_DS == 1) ){
						uint8_t *p_MAC = get_radio_tap_src_address( p_temp_packet );
						uint8_t *p_BSSID = get_radio_tap_BSSID( p_temp_packet );
						
						// If p_BSSID == p_MAC --> Must be from AP
						if ( compare_MAC( p_MAC, p_BSSID ) && !is_used( p_temp_packet ) ){
							// Set used, to prevent using the same packet in the future..
							set_used( p_temp_packet );
							return p_temp_packet;
						}
					}
				}
			}
		}
	}

	return NULL;
} 

static PACKET* find_client_authentication_match( PACKET* p_client_authentication_packet ){
	uint64_t authentication_time = get_radio_tap_time( p_client_authentication_packet );
	uint64_t disassociation_time;
	uint8_t *p_MAC_client = get_radio_tap_src_address( p_client_authentication_packet );

	for( int i = 0; i < LIST_SIZE; i++ ){
		PACKET *p_temp_packet = get_packet_from_list( i );

		if ( p_temp_packet != NULL ){
			if ( is_radio_tap_packet( p_temp_packet ) ){
				if ( get_radio_tap_type( p_temp_packet ) == TYPE_RADIO_TAP_DISASSOCIATION ){
					uint8_t *p_temp_MAC = get_radio_tap_src_address( p_temp_packet );

					// Check if disassociation is also from client
					if ( compare_MAC( p_MAC_client, p_temp_MAC ) ){
						disassociation_time = get_radio_tap_time( p_temp_packet );
						uint64_t diff =  ( authentication_time - disassociation_time ) / 1000;
						// Check if time in between is less then 100ms
						if ( diff < 100 ){
							sprintf( text, "WIFI NOTICE: %llums between disassociation and authentication of %s", diff, get_MAC_address_name( p_MAC_client ) );
							set_packet_text( p_client_authentication_packet, text );
							set_packet_text( p_temp_packet, text );
							send_WIFI_radio_tap_notice_to_message_bus( p_client_authentication_packet );
							send_WIFI_radio_tap_notice_to_message_bus( p_temp_packet );
						}
					}
				}
			}	
		}
	}

	return NULL;
}

void update_WIFI( void ){
	// Find an (not yet used) client authentication frame
	PACKET *p_client_authentication_packet = find_client_authentication();

	while ( p_client_authentication_packet != NULL ){
		// Find match, i.e., authentication and disassociation from same source with time in between < 100 ms
		find_client_authentication_match( p_client_authentication_packet );
		p_client_authentication_packet = find_client_authentication();
	}

	// Find AP or attacker sending disassociation 
	PACKET *p_temp_packet = find_AP_disassociation();
	if ( p_temp_packet != NULL ){
		sprintf( text, "WIFI NOTICE: Found AP or attacker sending disassociation, MAC=%s", get_MAC_address_name( get_radio_tap_src_address( p_temp_packet ) ) );
		set_packet_text( p_temp_packet, text );
		send_WIFI_radio_tap_notice_to_message_bus( p_temp_packet );
	}

	detect_short_time_between_data_frames();
}

void add_packet_to_WIFI( PACKET *p_packet ){
	if ( is_radio_tap_packet( p_packet ) ){
		add_packet_to_list( p_packet );
		//send_WIFI_radio_tap_notice_to_message_bus( p_packet );
	}
}




