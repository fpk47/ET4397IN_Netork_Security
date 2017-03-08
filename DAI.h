#ifndef DAI_H
#define DAI_H

#include "general_includes.h"
#include "packet.h"

void DAI_update( void );
void add_packet_to_DAI( PACKET *p_packet );

#endif