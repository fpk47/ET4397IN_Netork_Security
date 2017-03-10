#include "capture.h"

static char text[100];

static uint8_t IP4[4];

static void set_own_IP4( char* name ){
    int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, name, IFNAMSIZ-1);
    ioctl(fd, SIOCGIFADDR, &ifr);
    close(fd);

    /* display result */
    struct in_addr in = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;
    uint32_t ip_raw;

    for ( int i = 0; i < 4; i++ ){
        IP4[i] = *( ((uint8_t*) &(in.s_addr)) + i );
    }

    sprintf( text, "capture.c: set_own_IP4_address() --> IP address: %d.%d.%d.%d\n", IP4[0], IP4[1], IP4[2], IP4[3] );
    print_info( text );
}

uint8_t* get_own_IP4( void ){
    return IP4;
} 

pcap_t* open_devide( void ){
	char *p_device_name;
    char ip[18];
    char subnet_mask[13];
    bpf_u_int32 ip_raw; /* IP address as integer */
    bpf_u_int32 subnet_mask_raw; /* Subnet mask as integer */
    int lookup_return_code;
    struct in_addr address; /* Used for both ip & subnet */
	char error_buffer[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	int packet_count_limit = 1;
	int timeout_limit = 10000; /* In milliseconds */

    p_device_name = pcap_lookupdev( error_buffer );
    if ( p_device_name == NULL) {
        sprintf( text, "capture.c: open_devide() --> Error finding device: %s\n", error_buffer );
        print_error( text );
        exit(0);
    }

    /* Open device for live capture */
    handle = pcap_open_live(
            p_device_name,
            BUFSIZ,
            packet_count_limit,
            timeout_limit,
            error_buffer
        );

    set_own_IP4( p_device_name );
    print_info( "capture.c: open_devide(): Ready for capture!\n" );

    return handle;
}

PACKET* get_next_device_packet( DEVICE* p_device ){
	struct pcap_pkthdr packet_header;
	const u_char *data;
	data = pcap_next( p_device, &packet_header);
    if (data == NULL) {
        print_error( "capture.c: get_next_packet() --> No packet found.\n" );
        exit(0);
    }

    if (data == NULL) {
        print_error( "capture.c: get_next_packet() --> No packet found.\n" );
        exit(0);
    }

	if ( packet_header.caplen != packet_header.len ){
		print_debug( "capture.c: get_next_packet() --> packet_header.caplen != packet_header.len\n" );
        return NULL;
	}
    
    PACKET *p_packet = init_packet_u_char( packet_header.len, data );
    parse_packet( p_packet );

    return p_packet;
}