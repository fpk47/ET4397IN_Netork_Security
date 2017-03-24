#include "general_includes.h"
#include "pcap_file.h"
#include "capture.h"
#include "parser.h"
#include "packet.h"
#include "message.h"
#include "tools.h"
#include "configuration.h"
#include "message_bus.h"
#include "log.h"
#include "crc32.h"
#include "DAI.h"
#include "wifi.h"

static uint8_t packet_data[59] = { 
	0xbc, 0x5f, 0xf4, 0x68, 0x4e, 0x98, 0xb8, 0xe8, 0x56, 0x04, 0xc1, 0x6a, 0x08, 0x00, 0x45, 0x00,
	0x00, 0x29, 0xb1, 0x35, 0x00, 0x00, 0x40, 0x11, 0x45, 0x3a, 0xc0, 0xa8, 0x01, 0x86, 0xc0, 0xa8,
	0x01, 0x7e, 0x00, 0x50, 0x00, 0x50, 0x00, 0x15, 0xba, 0xd2, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20,
	0x77, 0x6f, 0x72, 0x6c, 0x64, 0x2e, 0x2e, 0x00, 0x00, 0x00, 0x00
};

static PACKET *p_local_packet; 


#define SAVE_TO_FILE TRUE
#define USE_FILE FALSE
#define USE_DEVICE TRUE

static char text[100];

/* SEE message.h to turn warnings, debug messages on or off */

static void init( void ){
	init_packet();
	init_message_bus(); 
	init_log();			// FIRST init_message_bus() THEN init_log()
	init_DAI(); 		// FIRST init_message_bus() THEN init_DAI()
	init_WIFI(); 		// FIRST init_message_bus() THEN init_WIFI()

	// You can set your own MAC address here..

	uint8_t MAC[6] = { 0xb8, 0x56, 0xe8, 0x04, 0xc1, 0x6a };
	set_own_MAC( MAC );


	p_local_packet = init_packet_uint8_t( 55, packet_data );
	parse_packet( p_local_packet, TYPE_ETHERNET );
	print_packet ( p_local_packet );
}

static void update_modules( void ){
	update_log();
	update_DAI();
	update_WIFI();
}

static void add_packet_to_modules( PACKET *p_packet ){
	if ( p_packet != NULL ){
		add_packet_to_DAI( p_packet );
		add_packet_to_WIFI( p_packet );
	}	
}

int main(int argc, char *argv[]) {	
	init();
	uint32_t counter = 0;

	DEVICE* p_device = open_devide();

	uint8_t MAC_src[6] = { 0xb8, 0xe8, 0x56, 0x04, 0xc1, 0x6a };
	uint8_t MAC_dst[6] = { 0xbc, 0x5f, 0xf4, 0x68, 0x4e, 0x98 };

	uint8_t IP_src[4] = { 192, 168, 1, 134 };
	uint8_t IP_dst[4] = { 192, 168, 1, 126 };

	while ( TRUE ){
		set_MAC_src( p_local_packet, MAC_src );
		set_MAC_dst( p_local_packet, MAC_dst );
		set_IP4_src( p_local_packet, IP_src );
		set_IP4_dst( p_local_packet, IP_dst );
		update_CFS( p_local_packet );
		pcap_inject( p_device, (const void *) get_data( p_local_packet ), get_size( p_local_packet ) );
		//print_packet( p_local_packet );
		printf( "counter: %d\n", counter++ );
	}
	
    return 0;
}