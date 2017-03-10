#ifndef DAI_H
#define DAI_H

#include "general_includes.h"
#include "packet.h"
#include "packet_list.h"
#include "configuration.h"
#include "message_bus.h"
#include "message.h"
#include "capture.h"

void init_DAI( void );
void update_DAI( void );
void add_packet_to_DAI( PACKET *p_packet );

#endif