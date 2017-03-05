###Question 2
To filter only TCP packets use the commands:

tcp  
ip.proto == 6

###How to run:
Run the run.sh script in the folder containing:

```c
gcc pcap_file.c tools.c message.c capture.c packet.c parser.c main.c -lpcap -o test.out
./test.out
```

Make sure to include the following files:

```c
#include "general_includes.h"
#include "pcap_file.h"
#include "capture.h"
#include "parser.h"
#include "packet.h"
#include "message.h"
#include "tools.h"
```

**pcap_file.h** contains all the functions regarding saving and loading packets to and from files. **capture.h** is an interface for reading live packets. **message.h** is an header file which specifies 4 function, _print\_info_, _print\_debug_, _print\_warning_ and _print\_error_ which gives the user some knowlegde what is going on. These can be turned on and off in **message.h** by changing the defines given there. **packet.h** contains all the functions needed for printing packets, checking if a packet is a IP, UDP, DNS etc packet as well as containing all the definitions (codes) for the RR_TYPES, UDP, TCP, IP4 etc. Also, **tools.h** saves all the strings (char[]) of the dns rr entries. i.e., 0x0cXX is converted to the string at the relative position 0xXX. It also takes care of loading uint23_t and uint16_t variables from the data as well as returning mac and ip addresses as strings. Finally **parser.h** takes care of the hard work, i.e., it parses all the raw data into the right **PACKET** structures which are later used for printing and (later for processing, filtering etc.)

###Open packets from file

```c
PCAP_FILE* p_pcap_file = open_pcap_file( "file.pcap" );
set_current_pcap_file( p_pcap_file );
	
PACKET *p_packet = NULL;

do{
	p_packet = get_next_pcap_file_packet();

	if ( p_packet != NULL ){
		print_packet( p_packet );
	}
} while ( p_packet != NULL );
```

All files are stored in de **data** folder. _set\_current\_pcap\_file_ sets the current file for the parser. Next, _get\_next\_pcap\_file\_packet_ loops through the packets until EOF.

###Save packet to file:

```c
PCAP_FILE_GLOBAL_HEADER* p_pcap_file_global_header;  
p_pcap_file_global_header = init_p__pcap_file_global_header( 0xa1b2c3d4, 2, 4, 0, 0, 0, 0 );
FILE *p_file = create_pcap_file( "new.pcap", p_pcap_file_global_header );

for ( "all packets" ){
	save_packet_to_pcap_file( p_file, p_packet, p_pcap_file_global_header );
}
```

A pcap file can be created with _create\_pcap\_file_. Next, a packet can be saved to an existing pcap with with _save\_packet\_to\_pcap\_file_. Finally, a packet can be openend to read packets with _open\_pcap\_file_.

##Capture live packets

```c
DEVICE* p_device = open_devide();

while ( TRUE ){
	PACKET *p_packet = get_next_device_packet( p_device );
	
	if ( is_dns_packet( p_packet ) ){
		print_packet( p_packet );
	}

	free_packet( p_packet );
}
```

###Output of print\_packet( PACKET *p_packet )

```
----PACKET (total size = 419)----
   ETHERNET: mac_dst     --> ac:bc:32:cc:a4:dd
   ETHERNET: mac_src     --> 00:1b:90:48:a4:00
   ETHERNET: size        --> 14
   ETHERNET: type        --> IP4
        IP4: ip4_dst     --> 145.94.177.168
        IP4: ip4_src     --> 8.8.8.8
        IP4: size        --> 20 [IHL = 5]
        IP4: protocol    --> UDP
        UDP: port_dst    --> 53
        UDP: port_src    --> 64719
        UDP: size        --> 8
        DNS: #query      --> 1
        DNS: #answer     --> 14
        DNS: #authority  --> 0
        DNS: #additional --> 0
        DNS: {QUERY} TYPE *A, CLASS IN, google.com
        DNS: {ANSWER} TYPE A, CLASS IN, TTL=299, length=4
           : 216.58.212.206
        DNS: {ANSWER} TYPE AAAA, CLASS IN, TTL=299, length=16
        DNS: {ANSWER} TYPE MX, CLASS IN, TTL=599, length=12
           : preferences = 656737
           : exhange = aspmx.l.google.com
        DNS: {ANSWER} TYPE NS, CLASS IN, TTL=86399, length=6
           : ns4.google.com
        DNS: {ANSWER} TYPE TXT, CLASS IN, TTL=3599, length=36
           : txt = #v=spf1 include:_spf.google.com ~all
        DNS: {ANSWER} TYPE MX, CLASS IN, TTL=599, length=9
           : preferences = 1311841
           : exhange = alt1.aspmx.l.google.com
        DNS: {ANSWER} TYPE SOA, CLASS IN, TTL=59, length=34
           : mname = TODO
           : rname = TODO
           : serial = 0x00000384
           : refresh = 0x00000384
           : retry = 0x00000708
           : expire = 0x0000003c
        DNS: {ANSWER} TYPE NS, CLASS IN, TTL=86399, length=6
           : ns1.google.com
        DNS: {ANSWER} TYPE MX, CLASS IN, TTL=599, length=9
           : preferences = 1967201
           : exhange = alt2.aspmx.l.google.com
        DNS: {ANSWER} [UKNOWN RR_TYPE 0x0101] length = 19  
        DNS: {ANSWER} TYPE NS, CLASS IN, TTL=86399, length=6
           : ns3.google.com
        DNS: {ANSWER} TYPE MX, CLASS IN, TTL=599, length=9
           : preferences = 3277921
           : exhange = alt4.aspmx.l.google.com
        DNS: {ANSWER} TYPE MX, CLASS IN, TTL=599, length=9
           : preferences = 2622561
           : exhange = alt3.aspmx.l.google.com
        DNS: {ANSWER} TYPE NS, CLASS IN, TTL=86399, length=6
           : ns2.google.com
-----------------
```

Note that **mname** and **rname** still need to be parsed correctly. I tried my best to parse the packets in a as clear as possible way. If the packet is no DNS packet the following output is shown, (the program does not crash):

```
----PACKET (total size = 52)----
   ETHERNET: mac_dst     --> 01:80:c2:00:00:00
   ETHERNET: mac_src     --> ac:22:0b:d1:58:64
   ETHERNET: size        --> 14
   ETHERNET: type        --> 0026 [NOT IP4, ABORTING]
-----------------
```
```
----PACKET (total size = 66)----
   ETHERNET: mac_dst     --> ac:22:0b:d1:58:60
   ETHERNET: mac_src     --> b8:e8:56:04:c1:6a
   ETHERNET: size        --> 14
   ETHERNET: type        --> IP4
        IP4: ip4_dst     --> 149.154.167.91
        IP4: ip4_src     --> 192.168.1.45
        IP4: size        --> 20 [IHL = 5]
        IP4: protocol    --> TCP
        TCP: port_dst    --> 443
        TCP: port_src.   --> 51789
        TCP: size        --> 32 [data_offset = 8]
        DNS: [NOT PORT 53, ABORTING], 
-----------------
```

### Important structs

####PACKET
The **PACKET** (struct packet) contains all the data once the packet is loaded from a **PCAP_FILE** or in capture.c. A **PACKET** can also be saved again to a file as shown above.

```
typedef struct packet{
	uint32_t size;
	uint8_t *p_data;

	ETHERNET_HEADER ethernet_header;
	IP_4_HEADER ip_4_header;
	UDP_HEADER udp_header;
	TCP_HEADER tcp_header;
	DNS_HEADER dns_header;

	RR_QUERY_ENTRY rr_query_entry;
	RR_ENTRY *p_rr_entries[NUMBER_OF_RR_ENTRIES];
} PACKET;
```

####PCAP

```
typedef struct pcap_file_global_header {
    uint32_t magic_number;   /* magic number */
    uint16_t version_major;  /* major version number */
    uint16_t version_minor;  /* minor version number */
    int32_t  this_zone;       /* GMT to local correction */
    uint32_t sig_figs;        /* accuracy of timestamps */
    uint32_t snap_len;        /* max length of captured packets, in octets */
    uint32_t network;        /* data link type */
} PCAP_FILE_GLOBAL_HEADER;

typedef struct pcap_file_entry_header {
    uint32_t ts_sec;         /* timestamp seconds */
    uint32_t ts_usec;        /* timestamp microseconds */
    uint32_t incl_len;       /* number of octets of packet saved in file */
    uint32_t orig_len;       /* actual length of packet */
    uint8_t padding[8];
} PCAP_FILE_ENTRY_HEADER;
```

**PCAP\_FILE\_GLOBAL\_HEADER** and **PCAP\_FILE\_ENTRY\_HEADER** are used to read packets in the function _get\_next\_device\_packet()_ (see above) and other function regarding loading and saving of packets in the pcap format. The structure shown below shows the format of a pcap file.

```
typedef struct pcap_file{
    uint32_t size;
    uint8_t *p_data;
} PCAP_FILE;
```
