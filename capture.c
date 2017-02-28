#include "capture.h"

static PCAP_PACKET* init_pcap_packet( uint32_t size, const u_char *data ){
	PCAP_PACKET* p_pcap_packet = (PCAP_PACKET*) malloc( sizeof( PCAP_PACKET ) );
	p_pcap_packet->p_data = (uint8_t*) malloc( size );
	p_pcap_packet->size = size;

	for( int i = 0; i < size; i++ ){
		p_pcap_packet->p_data[i] = data[i];
	}

	return p_pcap_packet;
}

void free_pcap_packet( PCAP_PACKET* p_pcap_packet ){
	free( p_pcap_packet->p_data );
	free( p_pcap_packet );
}

pcap_t* open_devide( void ){
	char *device;
	char error_buffer[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	int packet_count_limit = 1;
	int timeout_limit = 10000; /* In milliseconds */

    device = pcap_lookupdev( error_buffer );
    if (device == NULL) {
        printf("[ERROR] capture.c: open_devide() --> Error finding device: %s\n", error_buffer );
        exit(0);
    }

    /* Open device for live capture */
    handle = pcap_open_live(
            device,
            BUFSIZ,
            packet_count_limit,
            timeout_limit,
            error_buffer
        );

    return handle;
}

PCAP_PACKET* get_next_packet( pcap_t* handle ){
	struct pcap_pkthdr packet_header;
	const u_char *data;
	data = pcap_next( handle, &packet_header);
    if (data == NULL) {
        printf("[ERROR] capture.c: get_next_packet() --> No packet found.\n");
        exit(0);
    }

    if (data == NULL) {
        printf("[ERROR] capture.c: get_next_packet() --> No packet found.\n");
        exit(0);
    }

	if ( packet_header.caplen != packet_header.len ){
		printf("[WARNING] capture.c: get_next_packet() --> packet_header.caplen != packet_header.len\n");
        return NULL;
	}

    return init_pcap_packet( packet_header.len, data );
}