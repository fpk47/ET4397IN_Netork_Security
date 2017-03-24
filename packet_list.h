#ifndef PACKET_LIST_H
#define PACKET_LIST_H

#include "general_includes.h"
#include "message.h"
#include "packet.h"
#include "parser.h"

#define PACKET_LIST_MAX_NUMBER_OF_PACKETS 100

typedef struct packet_list{
	uint32_t type;
	PACKET *p_packets[ PACKET_LIST_MAX_NUMBER_OF_PACKETS ];
} PACKET_LIST;

PACKET_LIST* malloc_packet_list( uint32_t type );
uint32_t index_of_packet_in_packet_list( PACKET_LIST *p_packet_list, PACKET *p_packet );
void add_packet_to_packet_list( PACKET_LIST *p_packet_list, PACKET *p_packet );
PACKET* get_packet_from_packet_list( PACKET_LIST *p_packet_list, uint32_t index );
PACKET* remove_packet_from_packet_list( PACKET_LIST *p_packet_list, uint32_t index );
PACKET* remove_next_packet_from_packet_list( PACKET_LIST *p_packet_list );

#endif