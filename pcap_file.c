#include "pcap_file.h"

static char text[100];

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

PCAP_FILE* create_pcap_file( char* p_file_name ){
	char* p_address = text;
	sprintf( p_address, "./data/%s", p_file_name );
    FILE* p_file = fopen( p_address, "w+" );
    return NULL;
} 

PCAP_FILE* open_pcap_file( char* p_file_name ){
	char* p_address = text;
	sprintf( p_address, "./data/%s", p_file_name );
    FILE* p_file = fopen( p_address, "r+" );

    // Check if file exists...
	if ( 0 == access( p_address, 0 ) ){ 
	    fseek( p_file, 0L, SEEK_END );
    	uint32_t file_size = ftell( p_file ); 
    	rewind( p_file );

    	if ( file_size != 0 ){
    		PCAP_FILE* p_pcap_file = init_pcap_file_struct( file_size );
    		uint32_t bytes_read = fread( p_pcap_file->p_data, sizeof(uint8_t), file_size, p_file );

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