#ifndef MESSAGE_H
#define MESSAGE_H

#include "general_includes.h"

#define PRINT_INFO TRUE
#define PRINT_DEBUG FALSE
#define PRINT_WARNINGS TRUE
#define PRINT_ERROR TRUE

void print_info( char* p_text );
void print_debug( char* p_text );
void print_warning( char* p_text );
void print_error( char* p_text );

#endif