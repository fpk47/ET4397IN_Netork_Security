#include "pcap_file.h"
#include "message.h"
#include "packet.h"

static char text[100];

uint32_t get_size_pcap_entry_header( PCAP_FILE_GLOBAL_HEADER* p_pcap_file_global_header ){
	uint32_t temp = p_pcap_file_global_header->magic_number;
	if ( ( temp & 0x0000FFFF ) == 0xcd34 ){
		return 24;
	} else{
		return 16;
	}
}

static PCAP_FILE* init_pcap_file_struct( uint32_t size ){
	PCAP_FILE* p_pcap_file = (PCAP_FILE*) malloc( sizeof(PCAP_FILE) );
	p_pcap_file->p_data = (uint8_t*) malloc(size);
	p_pcap_file->size = size;
	return p_pcap_file;
}

void free_pcap_file( PCAP_FILE* p_pcap_file ){
	free( p_pcap_file->p_data );
	free( p_pcap_file );
}

uint32_t get_pcap_file_type( PCAP_FILE *p_pcap_file ){
    if ( p_pcap_file == NULL ){
        print_warning( "pcap_file.c: get_pcap_file_type() --> p_pcap_file == NULL\n" );
        return -1;
    }

    return p_pcap_file->type;
}

PCAP_FILE_GLOBAL_HEADER* init_p__pcap_file_global_header( uint32_t magic_number, uint16_t version_major, uint16_t version_minor, 
                                                          int32_t  this_zone, uint32_t sig_figs, uint32_t snap_len, uint32_t network ){
	PCAP_FILE_GLOBAL_HEADER *p_pcap_file_global_header = (PCAP_FILE_GLOBAL_HEADER*) malloc( sizeof( PCAP_FILE_GLOBAL_HEADER ) );

	p_pcap_file_global_header->magic_number = magic_number;
	p_pcap_file_global_header->version_major = version_major;
	p_pcap_file_global_header->version_minor = version_minor;
	p_pcap_file_global_header->this_zone = this_zone;
	p_pcap_file_global_header->sig_figs = sig_figs;
	p_pcap_file_global_header->snap_len = snap_len;
	p_pcap_file_global_header->network = network;

	return p_pcap_file_global_header;
}

PCAP_FILE_ENTRY_HEADER* init_pcap_file_entry_header( PACKET *p_packet ){
	PCAP_FILE_ENTRY_HEADER *p_pcap_file_entry_header = (PCAP_FILE_ENTRY_HEADER*) malloc( sizeof( PCAP_FILE_ENTRY_HEADER ) );
	struct timeval currentTime;
	gettimeofday(&currentTime, NULL);

	p_pcap_file_entry_header->ts_sec = (uint32_t) currentTime.tv_sec;
	p_pcap_file_entry_header->ts_usec = (uint32_t) currentTime.tv_usec;
	p_pcap_file_entry_header->incl_len = p_packet->size;
	p_pcap_file_entry_header->orig_len = p_packet->size;

	return p_pcap_file_entry_header;
}

FILE* create_pcap_file( char* p_file_name, PCAP_FILE_GLOBAL_HEADER* p_pcap_file_global_header ){
	sprintf( text, "./data/%s", p_file_name );
    FILE* p_file = fopen( text, "w+" );

    if ( p_file == NULL ){
    	print_warning( "pcap_file.c: create_pcap_file() --> p_file == NULL\n" );
    	return NULL;
    }

    uint32_t written_size = fwrite( p_pcap_file_global_header, sizeof(uint8_t), PCAP_FILE_GLOBAL_HEADER_SIZE, p_file );

    if ( written_size != PCAP_FILE_GLOBAL_HEADER_SIZE ){
    	print_warning( "pcap_file.c: create_pcap_file() --> written_size != PCAP_FILE_GLOBAL_HEADER_SIZE \n" );
    	return NULL;
    }

    return p_file;
} 

void close_pcap_file( FILE *p_file ){
	fclose( p_file );
}

void save_packet_to_pcap_file( FILE *p_file, PACKET *p_packet, PCAP_FILE_GLOBAL_HEADER* p_pcap_file_global_header ){
	if ( p_file == NULL ){
    	print_warning( "pcap_file.c: save_packet_to_pcap_file() --> p_file == NULL\n" );
    	return;
    }

	PCAP_FILE_ENTRY_HEADER* p_pcap_file_entry_header = init_pcap_file_entry_header( p_packet );
	uint32_t written_size = fwrite( p_pcap_file_entry_header, sizeof(uint8_t), get_size_pcap_entry_header( p_pcap_file_global_header ), p_file );

    if ( written_size != get_size_pcap_entry_header( p_pcap_file_global_header ) ){
    	print_warning( "pcap_file.c: save_packet_to_pcap_file() --> written_size != get_size_pcap_entry_header() \n" );
    	return;
    }

    written_size = fwrite( p_packet->p_data, sizeof(uint8_t), p_packet->size, p_file );

    if ( written_size != p_packet->size ){
    	print_warning( "pcap_file.c: save_packet_to_pcap_file() --> written_size != p_packet->size \n" );
    	return;
    }

    return;
}

PCAP_FILE* open_pcap_file( char* p_file_name, uint32_t type ){
	char* p_address = text;
	sprintf( p_address, "./data/%s", p_file_name );
    FILE* p_file = fopen( p_address, "r+" );

    if ( p_file == NULL ){
    	print_warning( "pcap_file.c: open_pcap_file() --> p_file == NULL\n" );
    	return NULL;
    }

    // Check if file exists...
	if ( 0 == access( p_address, 0 ) ){ 
	    fseek( p_file, 0L, SEEK_END );
    	uint32_t file_size = ftell( p_file ); 
    	rewind( p_file );

    	if ( file_size != 0 ){
    		PCAP_FILE* p_pcap_file = init_pcap_file_struct( file_size );
    		uint32_t bytes_read = fread( p_pcap_file->p_data, sizeof(uint8_t), file_size, p_file );

            if ( type != TYPE_ETHERNET && type != TYPE_RADIO_TAP ){
                print_error( "pcap_file.c: open_pcap_file() --> type != TYPE_ETHERNET && type != TYPE_RADIO_TAP\n" );
                exit(0);
            }

            p_pcap_file->type = type;

    		 if ( bytes_read != file_size ){
    		 	printf( "[ERROR] pcap_file.c: open_pcap_file() --> file_size != bytes_read\n" );
    		 	exit(0);
    		 } else{
    		 	return p_pcap_file;
    		 }
    	} else{
    		printf( "[ERROR] pcap_file.c: open_pcap_file() --> file_size == 0\n" );
    		exit(0);
    	}
	} else{
		printf( "[ERROR] pcap_file.c: open_pcap_file() --> [%s] does not exist\n", p_address );
		exit(0);
	}
	
    return NULL;
} 