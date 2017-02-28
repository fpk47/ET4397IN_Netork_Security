#include "parser.h"

void print_pcap_packet( PCAP_PACKET* p_pcap_packet ){
	uint32_t size = p_pcap_packet->size;
	uint8_t *p_data = p_pcap_packet->p_data;

    printf("----NEW PACKET (%d)----\n", size );

    for( int i = 0; i < size; i++ ){
        printf( "%x ", p_data[i] );
    }

    printf("\n---------------\n");
}

