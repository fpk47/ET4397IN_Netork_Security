#ifndef PARSER_H
#define PARSER_H

#include "general_includes.h"
#include "pcap_file.h"
#include "capture.h"

void parse_packet( PACKET *p_packet);

void set_current_pcap_file( PCAP_FILE* p_pcap_file );
PACKET* get_next_pcap_file_packet( void );

#endif