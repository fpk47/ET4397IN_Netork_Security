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

#define USE_FILE FALSE
#define USE_DEVICE TRUE

static char text[100];

/* SEE message.h to turn warnings, debug messages on or off */

static void init( void ){
	init_message_bus(); // FIRST init_message_bus() THEN init_log()
	init_log();			// FIRST init_message_bus() THEN init_log()
}

int main(int argc, char *argv[]) {
	init();

	/* SAVE TO FILE EXAMPLE 
		PCAP_FILE_GLOBAL_HEADER* p_pcap_file_global_header;  
		p_pcap_file_global_header = init_p__pcap_file_global_header( 0xa1b2c3d4, 2, 4, 0, 0, 0, 0 );
		FILE *p_file = create_pcap_file( "new.pcap", p_pcap_file_global_header );

		for ( "all packets" ){
			save_packet_to_pcap_file( p_file, p_packet, p_pcap_file_global_header );
		}
	*/


	//CONFIGURATION_FILE* p_configuration_file = open_configuration_file( "test.config" );
	//CONFIGURATION* p_configuration = create_configuration(p_configuration_file);
	//exit(0);

	if ( USE_FILE ){
		PCAP_FILE* p_pcap_file = open_pcap_file( "dnssample.pcap" );
		set_current_pcap_file( p_pcap_file );
			
		PACKET *p_packet = NULL;

		do{
			if ( p_packet != NULL ){
				free_packet( p_packet );
			}

			p_packet = get_next_pcap_file_packet();

			if ( p_packet != NULL ){
				print_packet( p_packet );
			}

		} while ( p_packet != NULL );
	} 

	if ( USE_DEVICE ){
		uint32_t counter = 0;
		CONFIGURATION *p_configuration = malloc_configuration();
		set_local_configuration( p_configuration );

		DEVICE* p_device = open_devide();

		while ( TRUE ){
			uint8_t counter = 0;
			PACKET *p_packet = get_next_device_packet( p_device );

			if ( p_packet != NULL ){
				uint8_t *p_MAC = get_ethernet_MAC_src( p_packet );
				uint8_t *p_IP = get_IP4_src( p_packet );
				uint32_t index =  index_of_ARP_entry_in_configuration( get_local_configuration(), p_MAC, p_IP );
				
				if ( index == -1 ){
					add_ARP_entry_to_configuration( get_local_configuration(), get_ethernet_MAC_src( p_packet ), get_IP4_src( p_packet ) );
					//remove_ARP_entry_from_configuration( get_local_configuration(), index_of_ARP_entry_in_configuration( get_local_configuration(), p_MAC, p_IP ) );
				}

				if ( is_dns_packet( p_packet ) ){
					print_packet( p_packet );
				}

				if ( is_arp_packet( p_packet ) ){
					print_packet( p_packet );
				}

				/*
				if ( counter >= 80 ){
					CONFIGURATION_FILE* p_configuration_file = create_configuration_file( get_local_configuration() );
					save_configuration_file( "test.config", p_configuration_file );
					exit(0);
				}
				*/

				free_packet( p_packet );
			}
		}
	}
	
    return 0;
}