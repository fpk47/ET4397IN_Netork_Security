#include "general_includes.h"
#include "pcap_file.h"
#include "capture.h"
#include "parser.h"
#include "packet.h"
#include "message.h"

#define USE_FILE FALSE
#define USE_DEVICE TRUE

int main(int argc, char *argv[]) {

	if ( USE_FILE ){
		PCAP_FILE* p_pcap_file = open_pcap_file( "dnssample.pcap" );
		set_current_pcap_file( p_pcap_file );

		PACKET* p_packets[100];
		PACKET *p_packet = NULL;
		uint32_t size = 0;

		do{
			p_packet = get_next_pcap_file_packet();

			if ( p_packet != NULL ){
				print_packet( p_packet );
				p_packets[size] = p_packet;
				size++;
			}
		} while (  p_packet != NULL );

		for ( int i = 0; i < size; i++ ){
			
		}
	} 

	if ( USE_DEVICE ){
		uint32_t counter = 0;
		DEVICE* p_device = open_devide();

		while ( TRUE ){
			PACKET *p_packet = get_next_device_packet( p_device );
			counter++;

			if ( is_dns_packet( p_packet ) ){
				print_packet( p_packet );
			//} else{
				//printf( ".\n" );
			}

			free_packet( p_packet );
		}
	}
	
    return 0;
}