#include "packet_list.h"

PACKET_LIST* malloc_packet_list( void ){
	PACKET_LIST* p_packet_list = (PACKET_LIST*) malloc( sizeof( PACKET_LIST ) );

	for ( int i = 0; i < PACKET_LIST_MAX_NUMBER_OF_PACKETS; i++ ){
		p_packet_list->p_packets[i] = NULL;
	}

	if ( p_packet_list == NULL ){
		print_warning( "packet_list.c: malloc_packet_list() --> p_packet_list == NULL\n" );
		return FALSE;
	}

	return p_packet_list;
}


uint32_t index_of_packet_in_packet_list( PACKET_LIST *p_packet_list, PACKET *p_packet ){
	if ( p_packet_list == NULL ){
		print_warning( "packet_list.c: index_of_packet_in_packet_list() --> p_packet_list == NULL\n" );
		return -1;
	}

	if ( p_packet == NULL ){
		print_warning( "packet_list.c: malloc_packet_list() --> p_packet == NULL\n" );
		return -1;
	}

	for ( int i = 0; i < PACKET_LIST_MAX_NUMBER_OF_PACKETS; i++ ){

		PACKET *p_temp_packet = p_packet_list->p_packets[i];
		
		if ( p_temp_packet != NULL ){
			if ( compare_packets( p_packet, p_temp_packet ) ){
				return i;
			}
		}
	}

	return -1;
}

void add_packet_to_packet_list( PACKET_LIST *p_packet_list, PACKET *p_packet ){
	if ( p_packet_list == NULL ){
		print_warning( "packet_list.c: add_packet_to_packet_list() --> p_packet_list == NULL\n" );
		return;
	}

	if ( p_packet == NULL ){
		print_warning( "packet_list.c: add_packet_to_packet_list() --> p_packet == NULL\n" );
		return;
	}

	for ( int i = 0; i < PACKET_LIST_MAX_NUMBER_OF_PACKETS; i++ ){
		if ( p_packet_list->p_packets[i] == NULL ){
			PACKET *p_temp_packet = clone_packet( p_packet );
			parse_packet( p_temp_packet );

			p_packet_list->p_packets[i] = p_temp_packet;
			return;
		}
	}

	print_warning( "packet_list.c: add_packet_to_packet_list() --> buffer full\n" );
	return;
}

PACKET* get_packet_from_packet_list( PACKET_LIST *p_packet_list, uint32_t index ){
	if ( p_packet_list == NULL ){
		print_warning( "packet_list.c: get_packet_from_packet_list() --> p_packet_list == NULL\n" );
		return NULL;
	}

	if ( index == -1 ){
		print_warning( "packet_list.c: get_packet_from_packet_list() --> index == -1\n" );
		return NULL;
	}

	if ( p_packet_list->p_packets[ index ] != NULL ){
		return p_packet_list->p_packets[ index ];
	} else{
		print_warning( "packet_list.c: add_packet_to_packet_list() --> p_packet_list->p_packets[ index ] == NULL\n" );
		return NULL;
	}
}

PACKET* remove_packet_from_packet_list( PACKET_LIST *p_packet_list, uint32_t index ){
	if ( p_packet_list == NULL ){
		print_warning( "packet_list.c: get_packet_from_packet_list() --> p_packet_list == NULL\n" );
		return NULL;
	}

	if ( index == -1 ){
		print_warning( "packet_list.c: get_packet_from_packet_list() --> index == -1\n" );
		return NULL;
	}

	if ( p_packet_list->p_packets[ index ] != NULL ){
		PACKET *p_temp_packet = p_packet_list->p_packets[ index ];
		p_packet_list->p_packets[ index ] = NULL;
		return p_temp_packet;
	} else{
		print_warning( "packet_list.c: add_packet_to_packet_list() --> p_packet_list->p_packets[ index ] == NULL\n" );
		return NULL;
	}
}

PACKET* remove_next_packet_from_packet_list( PACKET_LIST *p_packet_list ){
	if ( p_packet_list == NULL ){
		print_warning( "packet_list.c: add_packet_to_packet_list() --> p_packet_list == NULL\n" );
		return NULL;
	}

	for ( int i = 0; i < PACKET_LIST_MAX_NUMBER_OF_PACKETS; i++ ){
		if ( p_packet_list->p_packets[i] != NULL ){
			PACKET *p_temp_packet = p_packet_list->p_packets[i];
			p_packet_list->p_packets[i] = NULL;
			return p_temp_packet;
		}
	}

	return NULL;
}






