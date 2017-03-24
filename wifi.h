#ifndef WIFI_H
#define WIFI_H

#include "general_includes.h"
#include "packet.h"
#include "parser.h"
#include "message.h"
#include "message_bus.h"

void init_WIFI( void );
void update_WIFI( void );
void add_packet_to_WIFI( PACKET *p_packet );

#endif