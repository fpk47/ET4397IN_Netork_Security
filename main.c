#include "general_includes.h"
#include "pcap_file.h"
#include "capture.h"
#include "parser.h"
#include "packet.h"
#include "message.h"
#include "tools.h"

#define USE_FILE TRUE
#define USE_DEVICE FALSE

int main(int argc, char *argv[]) {

	/* SAVE TO FILE EXAMPLE 
		PCAP_FILE_GLOBAL_HEADER* p_pcap_file_global_header;  
		p_pcap_file_global_header = init_p__pcap_file_global_header( 0xa1b2c3d4, 2, 4, 0, 0, 0, 0 );
		FILE *p_file = create_pcap_file( "new.pcap", p_pcap_file_global_header );

		for ( "all packets" ){
			save_packet_to_pcap_file( p_file, p_packet, p_pcap_file_global_header );
		}
	*/

	if ( USE_FILE ){
		PCAP_FILE* p_pcap_file = open_pcap_file( "new.pcap" );
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
		DEVICE* p_device = open_devide();

		while ( TRUE ){
			PACKET *p_packet = get_next_device_packet( p_device );

			if ( is_dns_packet( p_packet ) ){
				print_packet( p_packet );
			}

			free_packet( p_packet );
		}
	}
	
    return 0;
}