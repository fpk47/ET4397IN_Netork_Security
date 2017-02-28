#include "general_includes.h"
#include "pcap_file.h"
#include "capture.h"
#include "parser.h"

int main(int argc, char *argv[]) {
	PCAP_FILE* pcap_file = open_pcap_file( "dnssample.pcap" );

	printf( "%x\n", pcap_file->p_data[0] );

	pcap_t* p_handle = open_devide();

	while (1){
		PCAP_PACKET* p_pcap_packet = get_next_packet( p_handle );

		if ( p_pcap_packet != NULL ){
			print_pcap_packet( p_pcap_packet );
			free_pcap_packet( p_pcap_packet );
		}
	}
	
    return 0;
}