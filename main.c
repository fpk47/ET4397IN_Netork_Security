#include "general_includes.h"
#include "pcap_file.h"
#include "capture.h"
#include "parser.h"
#include "packet.h"

int main(int argc, char *argv[]) {
	//PCAP_FILE* p_pcap_file = open_pcap_file( "test.pcap" );
	PCAP_FILE* p_pcap_file = open_pcap_file( "dnssample.pcap" );
	set_current_pcap_file( p_pcap_file );

	PACKET* p_packet;

	do{
		p_packet = get_next_pcap_file_packet();
		if ( p_packet != NULL ){
			print_packet( p_packet );
		}
	} while (  p_packet != NULL );
	
    return 0;
}