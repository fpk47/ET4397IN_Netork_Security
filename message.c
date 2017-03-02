#include "message.h"

void print_info( char* p_text ){
	if ( PRINT_INFO ){
		printf( "[INFO] %s", p_text );
	}
}

void print_debug( char* p_text ){
	if ( PRINT_DEBUG ){
		printf( "[DEBUG] %s", p_text );
	}
}

void print_warning( char* p_text ){
	if ( PRINT_WARNINGS ){
		printf( "[WARNING] %s", p_text );
	}
}

void print_error( char* p_text ){
	if ( PRINT_ERROR ){
		printf( "[ERROR] %s", p_text );
	}
}
