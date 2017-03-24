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

static char text[100];

/* SEE message.h to turn warnings, debug messages on or off */

static void init( void ){
	init_packet();
	init_message_bus(); 

	uint8_t MAC[6] = { 0xb8, 0xe8, 0x56, 0x04, 0xc1, 0x6a };
	set_own_MAC( MAC );
}


int main(int argc, char *argv[]) {
	init();
	uint32_t counter = 0;

	DEVICE* p_device = open_devide();

	while ( TRUE ){
		PACKET *p_packet = get_next_device_packet( p_device );

		if ( p_packet != NULL ){ 
			if ( compare_MAC( get_ethernet_MAC_src( p_packet ), get_own_MAC() ) == FALSE ){
				print_packet( p_packet );
			}
			
			free_packet( p_packet ); 
		}
	}
	
	
    return 0;
}