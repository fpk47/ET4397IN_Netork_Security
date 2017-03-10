#include "DAI.h"

#define MAX_NUMBER_OF_IP4_PAIRS 100

typedef struct IP4_pair{
	uint8_t IP4_1[4];
	uint8_t IP4_2[4];
} IP4_PAIR;

typedef struct IP4_pair_counter{
	uint32_t number_of_pairs;

	IP4_PAIR IP4_pairs[ MAX_NUMBER_OF_IP4_PAIRS ];
	uint32_t counter[ MAX_NUMBER_OF_IP4_PAIRS ];
} IP4_PAIR_COUNTER;

static char text[100];
static CONFIGURATION *p_local_configuration;
static LOCAL_MESSAGE_BUS *p_local_message_bus;
static PACKET_LIST *p_packet_list;

static IP4_PAIR_COUNTER IP4_pair_counter;

static void init_IP4_pair_counter(){
	IP4_pair_counter.number_of_pairs = 0;
}

static uint32_t get_IP4_pair_count( uint8_t *p_IP4_1, uint8_t *p_IP4_2 ){
	for ( int i = 0; i < IP4_pair_counter.number_of_pairs; i++ ){
		IP4_PAIR *p_IP4_pair = &( IP4_pair_counter.IP4_pairs[i] );

		uint32_t unique = TRUE;
		if ( compare_IP4( p_IP4_1, p_IP4_pair->IP4_1 ) && compare_IP4( p_IP4_2, p_IP4_pair->IP4_2 ) ){
			unique = FALSE;
		}

		if ( !unique ){
			IP4_pair_counter.counter[i] += 1;
			sprintf( text, "DAI.c: check_IP4_pair() --> existing entry { %s, %s, %d }\n", get_IP4_address_name( p_IP4_1 ), get_IP4_address_name( p_IP4_2 ), IP4_pair_counter.counter[i]  );
			print_info( text );
			return IP4_pair_counter.counter[i];
		}
	}

	return 1;
}

static uint32_t check_IP4_pair( uint8_t *p_IP4_1, uint8_t *p_IP4_2 ){
	for ( int i = 0; i < IP4_pair_counter.number_of_pairs; i++ ){
		IP4_PAIR *p_IP4_pair = &( IP4_pair_counter.IP4_pairs[i] );

		uint32_t unique = TRUE;
		if ( compare_IP4( p_IP4_1, p_IP4_pair->IP4_1 ) && compare_IP4( p_IP4_2, p_IP4_pair->IP4_2 ) ){
			unique = FALSE;
		}

		if ( !unique ){
			IP4_pair_counter.counter[i] += 1;
			sprintf( text, "DAI.c: check_IP4_pair() --> existing entry { %s, %s, %d }\n", get_IP4_address_name( p_IP4_1 ), get_IP4_address_name( p_IP4_2 ), IP4_pair_counter.counter[i]  );
			print_info( text );
			return IP4_pair_counter.counter[i];
		}
	}

	uint32_t number_of_pairs = IP4_pair_counter.number_of_pairs;

	if ( number_of_pairs < MAX_NUMBER_OF_IP4_PAIRS ){
		IP4_PAIR *p_IP4_pair = &( IP4_pair_counter.IP4_pairs[ number_of_pairs ] );
		uint32_t *p_counter = &( IP4_pair_counter.counter[ number_of_pairs ] );

		for ( int i = 0; i < 4; i++ ){
			p_IP4_pair->IP4_1[i] = p_IP4_1[i];
			p_IP4_pair->IP4_2[i] = p_IP4_2[i];
			*p_counter = 1;
		}

		IP4_pair_counter.number_of_pairs += 1;

		sprintf( text, "DAI.c: check_IP4_pair() --> new entry { %s, %s, %d }\n", get_IP4_address_name( p_IP4_1 ), get_IP4_address_name( p_IP4_2 ), *p_counter  );
		print_info( text );
		return *p_counter;
	}

	return 0;
}


void init_DAI( void ){
	uint8_t ARP_notice = UNSUBSCRIBED;
	uint8_t ARP_error = UNSUBSCRIBED;

	p_local_message_bus = create_message_bus_subscription( ARP_notice, ARP_error );

	p_packet_list = malloc_packet_list();
	p_local_configuration = malloc_configuration();

	init_IP4_pair_counter();
}

void update_DAI( void ){
	PACKET *p_packet = remove_next_packet_from_packet_list( p_packet_list );

	while( p_packet != NULL ){

		if ( is_ARP_request( p_packet ) ){

			//print_packet( p_packet );

			// CHECK FOR INCONSISTENCY IN NETWORK
			uint32_t count_1 = check_IP4_pair( get_ARP_IP4_src( p_packet ), get_ARP_IP4_dst( p_packet ) );
			if ( !compare_IP4( get_ARP_IP4_src( p_packet ), get_own_IP4() ) ){
				uint32_t count_2 = get_IP4_pair_count( get_own_IP4(), get_ARP_IP4_dst( p_packet ) );

				// If PAIR { OWN_IP, REMOTE_IP } occurs less then { CURRENT_IP, REMOTE_IP }
				if ( count_1 - count_2 > 3 ){
					sprintf( text, "DAI NOTICE: INCONSISTENCY: %s probably has no ARP entry of %s", get_IP4_address_name( get_ARP_IP4_src( p_packet ) ), get_IP4_address_name( get_ARP_IP4_dst( p_packet ) ) );
					set_packet_text( p_packet, text );
					send_ARP_notice_to_message_bus( p_packet );
				}
			}

			// NOTICE: ARP_SRC_MAC != ETH_SRC_MAC
			uint32_t same_MAC = compare_MAC( get_ethernet_MAC_src( p_packet ), get_ARP_MAC_src( p_packet ) );
			if( !same_MAC ){
				set_packet_text( p_packet, "DAI NOTICE: ARP_MAC != ETH_MAC" );
				send_ARP_notice_to_message_bus( p_packet );
			} 

			// NOTICE: ARP REQUEST NOT TO BROADCAST, I.E., ETH_MAC_DST != ff:ff:ff:ff:ff:ff
			same_MAC = compare_MAC( get_ethernet_MAC_dst( p_packet ), get_MAC_broadcast() );
			if( !same_MAC ){
				set_packet_text( p_packet, "DAI NOTICE: ARP REQUEST NOT TO BROADCAST" );
				send_ARP_notice_to_message_bus( p_packet );
			} 
		}

		if ( is_ARP_reply( p_packet ) ){

			// CHECK CONFIGURATION IF { IP4, MAC } PAIR IS VALID
			uint32_t index = index_of_ARP_entry_in_configuration( get_global_configuration(), get_ARP_MAC_src( p_packet ), get_ARP_IP4_src( p_packet ) );
			if ( index == -1 ){ // NO EXISITING RECORD --> REJECT
				set_packet_text( p_packet, "DAI ERROR: { IP4, MAC } pair NOT IN LIST" );
				send_ARP_error_to_message_bus( p_packet );
			}

			// SAVE YOUR ARP_TABLE LOCAL ( FOR OWN IP )
			uint32_t same_IP4 = compare_IP4( get_own_IP4(), get_ARP_IP4_dst( p_packet ) );
			if( same_IP4 ){
				add_ARP_entry_to_configuration( p_local_configuration, get_ARP_MAC_src( p_packet ), get_ARP_IP4_src( p_packet ) );
			}

			// NOTICE: ARP REPLY NOT TO UNICAST, I.E., ETH_MAC_DST == ff:ff:ff:ff:ff:ff
			uint32_t same_MAC = compare_MAC( get_ethernet_MAC_dst( p_packet ), get_MAC_broadcast() );
			if( same_MAC ){
				set_packet_text( p_packet, "DAI NOTICE: ARP REPLY NOT TO UNICAST" );
				send_ARP_notice_to_message_bus( p_packet );
			}

			// NOTICE: ARP_SRC_MAC != ETH_SRC_MAC
			same_MAC = compare_MAC( get_ethernet_MAC_src( p_packet ), get_ARP_MAC_src( p_packet ) );
			if( !same_MAC ){
				set_packet_text( p_packet, "DAI NOTICE: ARP_MAC != ETH_MAC" );
				send_ARP_notice_to_message_bus( p_packet );
			} 

			// ERROR: BIND TO BROADCAST
			same_MAC = compare_MAC( get_ARP_MAC_dst( p_packet ), get_MAC_broadcast() );
			if( same_MAC ){
				set_packet_text( p_packet, "DAI ERROR: BIND TO BROADCAST" );
				send_ARP_error_to_message_bus( p_packet );
			}
		}

		free_packet( p_packet );
		p_packet = remove_next_packet_from_packet_list( p_packet_list );
	}
}

void add_packet_to_DAI( PACKET *p_packet ){
	if ( p_packet == NULL ){
		print_warning( "DAI.c: add_packet_to_DAI() --> p_packet == NULL\n" );
		return;
	}

	if ( has_ARP_header( p_packet ) ){
		add_packet_to_packet_list( p_packet_list, p_packet );
	}
}

