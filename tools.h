#ifndef TOOLS_H
#define TOOLS_H

#include "general_includes.h"
#include "message.h"

void printBytes( uint32_t size, uint8_t *data );
void printBits( uint32_t size, uint8_t *data );
uint8_t checkBit( uint16_t bitNumber, uint8_t *data );

void swap_byte( uint8_t *p_byte );
void swap_variable( uint8_t *p_data, uint32_t size );

uint16_t get_uint16_t( uint8_t *p_data );
uint32_t get_uint32_t( uint8_t *p_data );
uint64_t get_uint64_t( uint8_t *p_data );

void set_uint16_t( uint8_t *p_data, uint16_t data );
void set_uint32_t( uint8_t *p_data, uint32_t data );
void set_uint64_t( uint8_t *p_data, uint64_t data );

void set_domain_name( char *p_name, uint32_t index, uint32_t length );

void set_IP4_address( uint8_t *p_data, uint8_t *p_IP4_address );
void set_MAC_address( uint8_t *p_data, uint8_t *p_MAC_address );

char* get_domain_name( char *p_text, uint32_t max_length );
char* get_MAC_address_name( uint8_t *p_data );
char* get_IP4_address_name( uint8_t *p_data );

#endif