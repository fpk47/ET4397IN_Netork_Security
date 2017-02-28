#ifndef PCAP_FILE_H
#define PCAP_FILE_H

#include "general_includes.h"

#define WRITE_OK 1
#define WRITE_ERROR 0

typedef struct pcap_file{
    uint32_t size;
    uint8_t *p_data;
} PCAP_FILE;

typedef struct pcap_file_global_header {
    uint32_t magic_number;   /* magic number */
    uint16_t version_major;  /* major version number */
    uint16_t version_minor;  /* minor version number */
    int32_t  thiszone;       /* GMT to local correction */
    uint32_t sigfigs;        /* accuracy of timestamps */
    uint32_t snaplen;        /* max length of captured packets, in octets */
    uint32_t network;        /* data link type */
} PCAP_FILE_GLOBAL_HEADER;

typedef struct pcap_file_entry_header {
    uint32_t ts_sec;         /* timestamp seconds */
    uint32_t ts_usec;        /* timestamp microseconds */
    uint32_t incl_len;       /* number of octets of packet saved in file */
    uint32_t orig_len;       /* actual length of packet */
} PCAP_FILE_ENTRY_HEADER;

void free_pcap_file( PCAP_FILE* pcap_file );

PCAP_FILE* create_pcap_file( char* pFile_name );
PCAP_FILE* open_pcap_file( char* pFile_name );

#endif