#include "tools.h"
static char memory[1000];
static uint8_t memory_length[1000];

static char text[200];
static uint8_t checkByte( uint8_t bit );

static uint32_t domain_replace( uint8_t* p_text, uint32_t *p_length ){
	for ( int i = 0; i < *p_length; i++ ){
		if ( p_text[i] == 0xc0 ){
			uint32_t index = p_text[i + 1];
			uint32_t added_length = memory_length[index];

			for ( int j = *p_length - 1; j > i + 2; j-- ){
				p_text[ j + added_length - 2 ] = p_text[j];
			}

			for ( int j = i; j < i + added_length; j++ ){
				p_text[j] = memory[ index - i + j ];
			}

			*p_length += ( added_length - 2 );

			return TRUE;
		}
	}

	return FALSE;
}

void swap_variable( uint8_t *p_data, uint32_t size ){
	uint8_t *p_temp = (uint8_t *) malloc( size );

	for ( int i = 0; i < size; i++ ){
		p_temp[size - i - 1] = p_data[i];
	}

	for ( int i = 0; i < size; i++ ){
		p_data[i] = p_temp[i];
	}

	free( p_temp );
}

uint16_t get_uint16_t( uint8_t *p_data ){
	uint16_t temp;
	memcpy( &(temp), p_data, 2 );

	swap_variable( (uint8_t*) &temp, 2 );
	return temp;
}

uint32_t get_uint32_t( uint8_t *p_data ){
	uint32_t temp;
	memcpy( &(temp), p_data, 4 );

	swap_variable( (uint8_t*) &temp, 4 );
	return temp;
}

void set_uint16_t( uint8_t *p_data, uint16_t data ){
	memcpy( p_data, (void*) &data, 2 );
	swap_variable( p_data, 2 );
}

void set_uint32_t( uint8_t *p_data, uint32_t data ){
	memcpy( p_data, (void*) &data, 4 );
	swap_variable( p_data, 4 );
}

void set_domain_name( char *p_name, uint32_t index, uint32_t length ){
	int temp_index = 0;
	while ( p_name[ temp_index ] == 0 ){
		temp_index++;
		length--;
	}

	for ( int i = index; i < index + length - temp_index; i++ ){
		memory[i] = p_name[i - index + temp_index];
	}

	memory_length[index] = length;
}

char* get_domain_name( char *p_name, uint32_t max_length ){
	uint32_t length = 0;
	while ( p_name[length] != 0 && length < max_length - 1 ){
		length++;
	}

	length++;

	uint32_t index = 0;
	while ( checkByte( p_name[ index ] ) ){
		index++;
	}

	uint32_t size = 0;

	for ( int i = index; i < length; i++ ){
		text[i - index] = p_name[ i ];
		size++;
	}

	uint32_t status = TRUE;
	do{
		status = domain_replace( (uint8_t*) text, &size );
	} while ( status );

	for( int i = 0; i < size; i++ ){
		if ( checkByte( text[ i ] ) ){
			text[ i ] = '.';
		}
	}

	return text;
}

char* get_MAC_address_name( uint8_t *p_data ){
    static char local_text_1[100];
	static char local_text_2[100];
	static uint32_t status = TRUE;

	if ( status ){
    	sprintf( local_text_1, "%02x:%02x:%02x:%02x:%02x:%02x", p_data[0], p_data[1], p_data[2], p_data[3], p_data[4], p_data[5] );
    	status = FALSE;
    	return local_text_1;
	} else{
		sprintf( local_text_2, "%02x:%02x:%02x:%02x:%02x:%02x", p_data[0], p_data[1], p_data[2], p_data[3], p_data[4], p_data[5] );
    	status = TRUE;
    	return local_text_2;
	}
}

char* get_IP4_address_name( uint8_t *p_data ){
	static char local_text_1[100];
	static char local_text_2[100];
	static uint32_t status = TRUE;

	if ( status ){
    	sprintf( local_text_1, "%d.%d.%d.%d", p_data[0], p_data[1], p_data[2], p_data[3] );
    	status = FALSE;
    	return local_text_1;
	} else{
		sprintf( local_text_2, "%d.%d.%d.%d", p_data[0], p_data[1], p_data[2], p_data[3] );
    	status = TRUE;
    	return local_text_2;
	}
}

uint8_t checkByte( uint8_t byte ){
	if ( byte < 0x01f && byte != 0x00 ){
		return TRUE;
	} else{
		return FALSE;
	}
}
