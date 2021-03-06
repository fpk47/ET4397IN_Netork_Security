#ifndef PCAP_FILE_H
#define PCAP_FILE_H

#include "general_includes.h"
#include "packet.h"

#define WRITE_OK 1
#define WRITE_ERROR 0

typedef struct pcap_file{
    uint32_t size;
    uint32_t type;
    uint8_t *p_data;
} PCAP_FILE;

typedef struct pcap_file_global_header {
    uint32_t magic_number;   /* magic number */
    uint16_t version_major;  /* major version number */
    uint16_t version_minor;  /* minor version number */
    int32_t  this_zone;       /* GMT to local correction */
    uint32_t sig_figs;        /* accuracy of timestamps */
    uint32_t snap_len;        /* max length of captured packets, in octets */
    uint32_t network;        /* data link type */
} PCAP_FILE_GLOBAL_HEADER;

#define PCAP_FILE_GLOBAL_HEADER_SIZE sizeof(PCAP_FILE_GLOBAL_HEADER)

typedef struct pcap_file_entry_header {
    uint32_t ts_sec;         /* timestamp seconds */
    uint32_t ts_usec;        /* timestamp microseconds */
    uint32_t incl_len;       /* number of octets of packet saved in file */
    uint32_t orig_len;       /* actual length of packet */
    uint8_t padding[8];
} PCAP_FILE_ENTRY_HEADER;

uint32_t get_size_pcap_entry_header( PCAP_FILE_GLOBAL_HEADER* p_pcap_file_global_header );

void free_pcap_file( PCAP_FILE* pcap_file );

PCAP_FILE_GLOBAL_HEADER* init_p__pcap_file_global_header( uint32_t magic_number, uint16_t version_major, uint16_t version_minor, 
                                                          int32_t  this_zone, uint32_t sig_figs, uint32_t snap_len, uint32_t network );

uint32_t get_pcap_file_type( PCAP_FILE *p_pcap_file );

FILE* create_pcap_file( char* pFile_name, PCAP_FILE_GLOBAL_HEADER* p_pcap_file_global_header );
void close_pcap_file( FILE *p_file );
void save_packet_to_pcap_file( FILE *p_file, PACKET *p, PCAP_FILE_GLOBAL_HEADER* p_pcap_file_global_header );
PCAP_FILE* open_pcap_file( char* pFile_name, uint32_t type );

#endif