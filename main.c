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
#include "DAI.h"

#define SAVE_TO_FILE TRUE
#define USE_FILE TRUE
#define USE_DEVICE FALSE

static char text[100];

/* SEE message.h to turn warnings, debug messages on or off */

static void init( void ){
	init_packet();
	init_message_bus(); 
	init_log();			// FIRST init_message_bus() THEN init_log()
	init_DAI(); 		// FIRST init_message_bus() THEN init_DAI()
}

static void update_modules( void ){
	update_log();
	update_DAI();
}

static void add_packet_to_modules( PACKET *p_packet ){
	if ( p_packet != NULL ){
		add_packet_to_DAI( p_packet );
	}	
}

int main(int argc, char *argv[]) {
	init();
	uint32_t counter = 0;

	PCAP_FILE_GLOBAL_HEADER* p_pcap_file_global_header;  
	p_pcap_file_global_header = init_p__pcap_file_global_header( 0xa1b2c3d4, 2, 4, 0, 0, 0, 0 );
	FILE *p_file = create_pcap_file( "save_demo.pcap", p_pcap_file_global_header );

	// "test.config"  is empty to be able to show that DAI can detect ERRORs..
	CONFIGURATION_FILE* p_configuration_file = open_configuration_file( "test.config" );
	CONFIGURATION *p_configuration = create_configuration( p_configuration_file );
	set_global_configuration( p_configuration );

	if ( USE_FILE ){
		DEVICE* p_device = open_devide(); // To get OWN IP4

		PCAP_FILE* p_pcap_file = open_pcap_file( "arp2.pcap" );
		set_current_pcap_file( p_pcap_file );

		PACKET *p_packet = NULL;

		do{
			if ( p_packet != NULL ){
				free_packet( p_packet );
			}

			p_packet = get_next_pcap_file_packet();

			if ( p_packet != NULL ){
				add_packet_to_modules( p_packet );
			}

			update_modules();
		} while ( p_packet != NULL );
	} 

	if ( USE_DEVICE ){
		uint32_t counter = 0;

		DEVICE* p_device = open_devide();

		while ( TRUE ){
			PACKET *p_packet = get_next_device_packet( p_device );

			if ( p_packet != NULL ){ 
				add_packet_to_modules( p_packet );

				counter++;

				if ( counter % 100 == 0 ){
					printf("%d\n", counter );
				}

				if ( SAVE_TO_FILE ){
					save_packet_to_pcap_file( p_file, p_packet, p_pcap_file_global_header );
				}

				free_packet( p_packet ); 
			}

			update_modules();
		}
	}
	
    return 0;
}