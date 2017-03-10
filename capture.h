#ifndef CAPTURE_H
#define CAPTURE_H

#include "general_includes.h"
#include "packet.h"
#include "message.h"
#include "parser.h"

typedef pcap_t DEVICE;

uint8_t* get_own_IP4( void );
DEVICE* open_devide( void );
PACKET* get_next_device_packet( pcap_t* p_handle );



#endif