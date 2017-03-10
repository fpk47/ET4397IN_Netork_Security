#ifndef CONFIGURATION_H
#define CONFIGURATION_H

#include "general_includes.h"
#include "message.h"
#include "tools.h"

#define CONFIGURATION_FILE_PREFIX 0x8999
#define CONFIGURATION_ARP_ENTRY_TYPE 0x0001

#define CONFIGURATION_HEADER_LENGTH 4
#define CONFIGURATION_ARP_ENTRY_LENGTH 10

#define CONFIGURATION_MAX_ARP_ENTRIES 100

typedef struct ARP_entry{
	uint8_t MAC[6];
	uint8_t IP4[4];
} ARP_ENTRY;

typedef struct configuration_file{
    uint32_t size;
    uint8_t *p_data;
} CONFIGURATION_FILE;

typedef struct configuration{
    uint32_t number_of_ARP_entries;
    ARP_ENTRY *p_ARP_entries[CONFIGURATION_MAX_ARP_ENTRIES];
} CONFIGURATION;

void free_configuration_file( CONFIGURATION_FILE* p_configuration_file );
void free_configuration( CONFIGURATION *p_configuration );
void free_ARP_entry( ARP_ENTRY *p_ARP_entry );

CONFIGURATION_FILE* create_configuration_file( CONFIGURATION* p_configuration );
CONFIGURATION* create_configuration( CONFIGURATION_FILE* p_configuration_file );
CONFIGURATION* malloc_configuration( void );

CONFIGURATION_FILE* open_configuration_file( char* p_file_name );
void save_configuration_file( char* p_file_name, CONFIGURATION_FILE* p_configuration_file );
CONFIGURATION* get_global_configuration( void ); 
void set_global_configuration( CONFIGURATION* p_configuration ); 

void add_ARP_entry_to_configuration( CONFIGURATION* p_configuration, uint8_t *p_MAC, uint8_t *p_IP4 );
uint32_t index_of_ARP_entry_in_configuration( CONFIGURATION* p_configuration, uint8_t *p_MAC, uint8_t *p_IP4 );
void remove_ARP_entry_from_configuration( CONFIGURATION* p_configuration, uint32_t index );
uint32_t get_number_of_ARP_entries_in_configuration( CONFIGURATION* p_configuration );

#endif