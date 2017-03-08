#include "configuration.h"

static char text[200];
static CONFIGURATION* p_local_configuration = NULL;

static uint32_t compare_ARP_entry( ARP_ENTRY* p_ARP_entry, uint8_t *p_MAC, uint8_t *p_IP4 ){
	if ( p_ARP_entry == NULL ){
		print_warning( "configuration: malloc_ARP_entry() --> p_ARP_entry == NULL\n" );
		return FALSE;
	}

	if ( p_MAC == NULL ){
		print_warning( "configuration: malloc_ARP_entry() --> p_MAC == NULL\n" );
		return FALSE;
	}

	if ( p_IP4 == NULL ){
		print_warning( "configuration: malloc_ARP_entry() --> p_IP4 == NULL\n" );
		return FALSE;
	}

	for( int i = 0; i < 6; i++ ){
		if ( p_ARP_entry->MAC[i] != p_MAC[i] ){
			return FALSE;
		}
	}

	for( int i = 0; i < 4; i++ ){
		if ( p_ARP_entry->IP4[i] != p_IP4[i] ){
			return FALSE;
		}
	}

	return TRUE;
}

static ARP_ENTRY* malloc_ARP_entry( uint8_t *p_MAC, uint8_t *p_IP4 ){
	if ( p_MAC == NULL ){
		print_warning( "configuration: malloc_ARP_entry() --> p_MAC == NULL\n" );
		return NULL;
	}

	if ( p_IP4 == NULL ){
		print_warning( "configuration: malloc_ARP_entry() --> p_IP4 == NULL\n" );
		return NULL;
	}

	ARP_ENTRY* p_ARP_entry = (ARP_ENTRY*) malloc( sizeof( ARP_ENTRY ) );

	for( int i = 0; i < 4; i++ ){
		p_ARP_entry->IP4[i] = p_IP4[i];
	}

	for( int i = 0; i < 6; i++ ){
		p_ARP_entry->MAC[i] = p_MAC[i];
	}

	return p_ARP_entry;
}

static CONFIGURATION_FILE* malloc_configuration_file( uint32_t size ){
	CONFIGURATION_FILE* p_configuration_file = (CONFIGURATION_FILE*) malloc( sizeof( CONFIGURATION_FILE ) );
	p_configuration_file->p_data = (uint8_t*) malloc(size);
	p_configuration_file->size = size;
	return p_configuration_file;
}

void free_configuration_file( CONFIGURATION_FILE* p_configuration_file ){
	if ( p_configuration_file == NULL ){
		print_warning( "configuration: free_configuration_file() --> p_configuration_file == NULL\n" );
		return;
	}

	free( p_configuration_file->p_data );
	free( p_configuration_file );
	return;
}

void free_configuration( CONFIGURATION *p_configuration ){
	if ( p_configuration == NULL ){
		print_warning( "configuration: free_configuration() --> p_configuration == NULL\n" );
		return;
	}

	for ( int i = 0; i < CONFIGURATION_MAX_ARP_ENTRIES; i++ ){
		if ( p_configuration->p_ARP_entries[i] == NULL ){
			free_ARP_entry( p_configuration->p_ARP_entries[i] );
		}
	}

	free( p_configuration );
	return;
}

void free_ARP_entry( ARP_ENTRY *p_ARP_entry ){
	if ( p_ARP_entry == NULL ){
		print_warning( "configuration: free_ARP_entry() --> p_ARP_entry == NULL\n" );
		return;
	}

	free( p_ARP_entry );
}

CONFIGURATION_FILE* create_configuration_file( CONFIGURATION* p_configuration ){
	if ( p_configuration == NULL ){
		print_warning( "configuration: create_configuration_file() --> p_configuration == NULL\n" );
		return NULL;
	}
	
	uint32_t size = get_number_of_ARP_entries_in_configuration( p_configuration ) * ( CONFIGURATION_ARP_ENTRY_LENGTH + CONFIGURATION_HEADER_LENGTH );
	CONFIGURATION_FILE* p_configuration_file = malloc_configuration_file( size );

	uint32_t index = 0;
	uint8_t *p_data = p_configuration_file->p_data;

	for ( int i = 0; i < CONFIGURATION_MAX_ARP_ENTRIES; i++ ){
		ARP_ENTRY *p_ARP_entry = p_configuration->p_ARP_entries[i];

		if ( p_ARP_entry != NULL ){
			set_uint16_t( &(p_data[ index ]), CONFIGURATION_ARP_ENTRY_TYPE );		index += 2;
			set_uint16_t( &(p_data[ index ]), CONFIGURATION_ARP_ENTRY_LENGTH );		index += 2;

			for( int i = 0; i < 6; i++ ){
				p_data[ index ] = p_data[ index ] = p_ARP_entry->MAC[i]; 		index += 1;
			}

			for( int i = 0; i < 4; i++ ){
				p_data[ index ] = p_ARP_entry->IP4[i]; 							index += 1;
			}
		}
	}	

	return p_configuration_file;
}

CONFIGURATION* create_configuration( CONFIGURATION_FILE* p_configuration_file ){
    if ( p_configuration_file == NULL ){
    	print_warning( "configuration.c: create_configuration() --> p_configuration_file == NULL\n" );
    	return NULL;
    }

    uint32_t index = 0;
    uint8_t *p_data = p_configuration_file->p_data;
    uint32_t prefix = get_uint16_t( &(p_data[ index ]) ); 	
    index += 2;

    if ( prefix != CONFIGURATION_FILE_PREFIX ){
    	sprintf( text, "configuration.c: create_configuration() --> prefix != CONFIGURATION_FILE_PREFIX (prefix = %04x)\n", prefix );
    	print_warning( text );
    	return NULL;
    }

    uint32_t size = get_uint32_t( &(p_data[ index ]) ); index += 4; 

    p_data = &(p_data[ index ]);
    index = 0;

    while ( index < size ){
    	uint16_t type = get_uint16_t( &(p_data[ index ]) ); index += 2; 
    	uint16_t size = get_uint16_t( &(p_data[ index ]) ); index += 2; 

    	if ( type == CONFIGURATION_ARP_ENTRY_TYPE ){
    		sprintf( text, "MAC = %s,", get_MAC_address( &(p_data[ index ]) ) ); 
    		sprintf( text, "%s IP4 = %s\n", text, get_IP4_address( &(p_data[ index + 6 ]) ) ); 
    		print_info( text ); 
    	}

    	index += size; 
    }

    return NULL;
}

CONFIGURATION* malloc_configuration( void ){
	CONFIGURATION* p_configuration = (CONFIGURATION*) malloc( sizeof( CONFIGURATION ) );

	p_configuration->number_of_ARP_entries = 0;

	for ( int i = 0; i < CONFIGURATION_MAX_ARP_ENTRIES; i++ ){
		p_configuration->p_ARP_entries[i] = NULL;
	}

	return p_configuration;
}

CONFIGURATION_FILE* open_configuration_file( char* p_file_name ){
	static char address[100];

	sprintf( address, "./configurations/%s", p_file_name );
    FILE* p_file = fopen( address, "r+" );

    if ( p_file == NULL ){
    	print_warning( "configuration.c: save_configuration_file() --> p_file == NULL (probably no folder configurations..)\n" );
    	return NULL;
    }

        // Check if file exists...
	if ( 0 == access( address, 0 ) ){ 
	    fseek( p_file, 0L, SEEK_END );
    	uint32_t file_size = ftell( p_file ); 
    	rewind( p_file );

    	if ( file_size != 0 ){
    		CONFIGURATION_FILE* p_configuration_file = malloc_configuration_file( file_size );
    		uint32_t bytes_read = fread( p_configuration_file->p_data, sizeof(uint8_t), file_size, p_file );

    		 if ( bytes_read != file_size ){
    		 	print_error( "configuration.c: open_configuration_file() --> file_size != bytes_read\n" );
    		 	free_configuration_file( p_configuration_file );
    		 	exit(0);
    		 } else{
    		 	p_configuration_file->size = file_size;
    		 	return p_configuration_file;
    		 }
    	} else{
    		print_error( "configuration.c: open_configuration_file() --> file_size == 0\n" );
    		exit(0);
    	}
	} else{
		sprintf( text, "configuration.c: open_configuration_file() --> [%s] does not exist\n", address );
		print_error( text );
		exit(0);
	}
	
    return NULL;
}

void save_configuration_file( char *p_file_name, CONFIGURATION_FILE* p_configuration_file ){
	sprintf( text, "./configurations/%s", p_file_name );
    FILE* p_file = fopen( text, "w+" );

    if ( p_file == NULL ){
    	print_warning( "configuration.c: save_configuration_file() --> p_file == NULL (probably no folder configurations..)\n" );
    	return;
    }

    uint16_t prefix = CONFIGURATION_FILE_PREFIX;
    swap_variable( (uint8_t*) &prefix, 2 );

    uint32_t written_size = fwrite( &prefix, sizeof(uint8_t), sizeof(uint16_t), p_file );

    if ( written_size != sizeof(uint16_t) ){
    	print_warning( "configuration.c: save_configuration_file() --> written_size != sizeof(uint16_t) (prefix)\n" );
    }

    uint32_t size = p_configuration_file->size;
    swap_variable( (uint8_t*) &size, 4 );
    written_size = fwrite( &size, sizeof(uint8_t), sizeof(uint32_t), p_file );

    if ( written_size != sizeof(uint32_t) ){
    	print_warning( "configuration.c: save_configuration_file() --> written_size != sizeof(uint32_t) (p_configuration_file->size)\n" );
    }

    written_size = fwrite( p_configuration_file->p_data, sizeof(uint8_t), p_configuration_file->size, p_file );

    if ( written_size != p_configuration_file->size ){
    	print_warning( "configuration.c: save_configuration_file() --> written_size != p_configuration_file->size\n" );
    }

	fclose(p_file);

	sprintf( text, "configuration.c: save_configuration_file() --> saved [./configurations/%s]\n", p_file_name );
	print_info( text );
	return;
}

CONFIGURATION* get_local_configuration( void ){
	if ( p_local_configuration == NULL ){
		print_warning( "configuration: get_local_configuration() --> p_local_configuration == NULL\n" );
		return NULL;
	}

	return p_local_configuration;
}

void set_local_configuration( CONFIGURATION* p_configuration ){
	if ( p_configuration == NULL ){
		print_warning( "configuration: set_local_configuration() --> p_configuration == NULL\n" );
		return;
	}

	if ( p_local_configuration != NULL ){
		free_configuration( p_local_configuration );
	}

	p_local_configuration = p_configuration;
}

void add_ARP_entry_to_configuration( CONFIGURATION* p_configuration, uint8_t *p_MAC, uint8_t *p_IP4 ){
	if ( p_configuration == NULL ){
		print_warning( "configuration: set_local_configuration() --> p_configuration == NULL\n" );
		return;
	}

	if ( get_number_of_ARP_entries_in_configuration( p_configuration ) >= CONFIGURATION_MAX_ARP_ENTRIES ){
		print_warning( "configuration: set_local_configuration() --> get_number_of_ARP_entries_in_configuration( p_configuration ) >= CONFIGURATION_MAX_ARP_ENTRIES\n" );
		return;
	}

	ARP_ENTRY *p_ARP_entry = malloc_ARP_entry( p_MAC, p_IP4 );

	for ( int i = 0; i < CONFIGURATION_MAX_ARP_ENTRIES; i++ ){
		if ( p_configuration->p_ARP_entries[i] == NULL ){
			p_configuration->p_ARP_entries[i] = p_ARP_entry;
			p_configuration->number_of_ARP_entries += 1;
			return;
		}
	}

	return;
}

uint32_t index_of_ARP_entry_in_configuration( CONFIGURATION* p_configuration, uint8_t *p_MAC, uint8_t *p_IP4 ){
	if ( p_configuration == NULL ){
		print_warning( "configuration: index_of_ARP_entry_in_configuration() --> p_configuration == NULL\n" );
		return -1;
	}

	if ( p_MAC == NULL ){
		print_warning( "configuration: index_of_ARP_entry_in_configuration() --> p_MAC == NULL\n" );
		return -1;
	}

	if ( p_IP4 == NULL ){
		print_warning( "configuration: index_of_ARP_entry_in_configuration() --> p_MAC == NULL\n" );
		return -1;
	}

	for ( int i = 0; i < CONFIGURATION_MAX_ARP_ENTRIES; i++ ){
		ARP_ENTRY *p_ARP_entry = p_configuration->p_ARP_entries[i];

		if ( p_ARP_entry != NULL ){
			if ( compare_ARP_entry( p_ARP_entry, p_MAC, p_IP4 ) ){
				return i;
			}
		}
	}

	return -1;
}

void remove_ARP_entry_from_configuration( CONFIGURATION* p_configuration, uint32_t index ){
	if ( p_configuration == NULL ){
		print_warning( "configuration: remove_ARP_entry_from_configuration() --> p_configuration == NULL\n" );
		return;
	}

	if ( index == -1 ){
		print_warning( "configuration: remove_ARP_entry_from_configuration() --> index == -1\n" );
		return;
	}

	ARP_ENTRY *p_ARP_entry = p_configuration->p_ARP_entries[index];

	if ( p_ARP_entry == NULL ){
		print_warning( "configuration: remove_ARP_entry_from_configuration() --> p_ARP_entry == NULL\n" );
		return;
	}

	free_ARP_entry( p_ARP_entry );
	p_configuration->p_ARP_entries[index] = NULL;
	p_configuration->number_of_ARP_entries -= 1;
	return;
}

uint32_t get_number_of_ARP_entries_in_configuration( CONFIGURATION* p_configuration ){
	if ( p_configuration == NULL ){
		print_warning( "configuration: get_number_of_ARP_entries_in_configuration() --> p_configuration == NULL\n" );
		return - 1;
	}

	return p_configuration->number_of_ARP_entries;
}





