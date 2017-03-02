#include "capture.h"
#include "message.h"

static char text[100];

pcap_t* open_devide( void ){
	char *device;
	char error_buffer[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	int packet_count_limit = 1;
	int timeout_limit = 10000; /* In milliseconds */

    device = pcap_lookupdev( error_buffer );
    if (device == NULL) {
        sprintf( text, "capture.c: open_devide() --> Error finding device: %s\n", error_buffer );
        print_error( text );
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

PACKET* get_next_device_packet( pcap_t* handle ){
	struct pcap_pkthdr packet_header;
	const u_char *data;
	data = pcap_next( handle, &packet_header);
    if (data == NULL) {
        print_error( "capture.c: get_next_packet() --> No packet found.\n" );
        exit(0);
    }

    if (data == NULL) {
        print_error( "capture.c: get_next_packet() --> No packet found.\n" );
        exit(0);
    }

	if ( packet_header.caplen != packet_header.len ){
		print_warning( "capture.c: get_next_packet() --> packet_header.caplen != packet_header.len\n" );
        return NULL;
	}

    return init_packet_u_char( packet_header.len, data );
}