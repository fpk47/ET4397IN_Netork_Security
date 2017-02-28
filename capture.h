#ifndef CAPTURE_H
#define CAPTURE_H

#include "general_includes.h"

typedef struct pcap_packet{
	uint32_t size;
	uint8_t *p_data;
} PCAP_PACKET;

void free_pcap_packet( PCAP_PACKET* p_pcap_packet );

pcap_t* open_devide( void );
PCAP_PACKET* get_next_packet( pcap_t* p_handle );

#endif