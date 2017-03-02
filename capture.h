#ifndef CAPTURE_H
#define CAPTURE_H

#include "general_includes.h"
#include "packet.h"

pcap_t* open_devide( void );
PACKET* get_next_device_packet( pcap_t* p_handle );

#endif