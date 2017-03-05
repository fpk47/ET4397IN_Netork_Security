#ifndef TOOLS_H
#define TOOLS_H

#include "general_includes.h"

uint16_t get_uint16_t( uint8_t *p_data );
uint32_t get_uint32_t( uint8_t *p_data );

void set_domain_name( char *p_name, uint32_t index, uint32_t length );

char* get_domain_name( char *p_text, uint32_t max_length );
char* get_mac_address( uint8_t *p_data );
char* get_ip_4_address( uint8_t *p_data );

#endif