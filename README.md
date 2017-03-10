###Question 1

###Question 2

###Question 3

###How to run:
Run the run.sh script in the folder containing:

```c
gcc pcap_file.c packet_list.c tools.c configuration.c 
message.c DAI.c log.c message_bus.c capture.c 
packet.c parser.c main.c -lpcap -o test.out
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
#include "configuration.h"
#include "message_bus.h"
#include "log.h"
#include "DAI.h"
```

**pcap_file.h** contains all the functions regarding saving and loading packets to and from files. **capture.h** is an interface for reading live packets. **message.h** is an header file which specifies 4 function, _print\_info_, _print\_debug_, _print\_warning_ and _print\_error_ which gives the user some knowlegde what is going on. These can be turned on and off in **message.h** by changing the defines given there. **packet.h** contains all the functions needed for printing packets, checking if a packet is a IP, UDP, DNS etc packet as well as containing all the definitions (codes) for the RR_TYPES, UDP, TCP, IP4 etc. Also, **tools.h** saves all the strings (char[]) of the dns rr entries. i.e., 0x0cXX is converted to the string at the relative position 0xXX. It also takes care of loading uint23_t and uint16_t variables from the data as well as returning mac and ip addresses as strings. Finally **parser.h** takes care of the hard work, i.e., it parses all the raw data into the right **PACKET** structures which are later used for printing and (later for processing, filtering etc.)

### configuration.h

In **configuration.h** configurations can be loaded saved and created locally. A CONFIGURATION_FILE (struct) is the interface for the data on the disc. CONFIGURATION (struct) is the interface for working with configurations in the code. You can make a local CONFIGURATION or use the global CONFIGURATION  available in all the .c files. **All the files are openend en saved in ./configurations/** See the following functions:

```
CONFIGURATION_FILE* create_configuration_file( CONFIGURATION* p_configuration );
```

create a CONFIGURATION_FILE from a CONFIGURATION. This can happen when you create a CONFIGURATION locally and now want to save it to the disk.

```
CONFIGURATION* create_configuration( CONFIGURATION_FILE* p_configuration_file );
```

create a CONFIGURATION from a CONFIGURATION_FILE. This can happen when you loaded a file from the disk and now want to use the CONFIGURATION locally.

```
CONFIGURATION_FILE* open_configuration_file( char* p_file_name );
```

Create a CONFIGURATION_FILE by opening it on the disk.

```
void save_configuration_file( char* p_file_name, CONFIGURATION_FILE* p_configuration_file );
```

Save a CONFIGURATION_FILE to the disk.


```
CONFIGURATION* get_global_configuration( void ); 
```

Get the pointer to the global CONFIGURATION struct. With this mechanism you can add / remove / edit the CONFIGURATION in all .c files. (if **configuration.h** is included..)

```
void set_global_configuration( CONFIGURATION* p_configuration ); 
```

Set the global CONFIGURATION, this should only happens once when the program is start up.

```
void add_ARP_entry_to_configuration( CONFIGURATION* p_configuration, uint8_t *p_MAC, uint8_t *p_IP4 );
```

First see the structs:

```
typedef struct ARP_entry{
	uint8_t MAC[6];
	uint8_t IP4[4];
} ARP_ENTRY;
```


```
typedef struct configuration{
    uint32_t number_of_ARP_entries;
    ARP_ENTRY *p_ARP_entries[CONFIGURATION_MAX_ARP_ENTRIES];
} CONFIGURATION;
```

As you can see, for now, a CONFIGURATION only consists of ARP_ENTRYs ( [IP4, MAC] ). Additional elements can be easily added in the future.

```
uint32_t index_of_ARP_entry_in_configuration( CONFIGURATION* p_configuration, uint8_t *p_MAC, uint8_t *p_IP4 );
```

Returns the index of a ARP_ENTRY from the CONFIGURATION. If the ARP_ENTRY is not included in the CONFIGURATION -1 is returned.

```
void remove_ARP_entry_from_configuration( CONFIGURATION* p_configuration, uint32_t index );
```

Remove a ARP_ENTRY from a CONFIGURATION given an index.

```
uint32_t get_number_of_ARP_entries_in_configuration( CONFIGURATION* p_configuration );
```

Get the number of ARP_ENTRYs from a CONFIGURATION. Finally see this example where the difference is shown how the use the global and local CONFIGURATIONs

```
CONFIGURATION_FILE* p_configuration_file = open_configuration_file( "test.config" );
CONFIGURATION *p_configuration = create_configuration( p_configuration_file );
set_global_configuration( p_configuration );

1: uint32_t count_1 get_number_of_ARP_entries_in_configuration( get_global_configuration() )
2: uint32_t count_1 get_number_of_ARP_entries_in_configuration( p_configuration )
```

Note that 1: and 2: have same output now. However, if 2: was called in another function _p\_configuration_ is not kwon or a different pointer. Using _get\_global\_configuration()_ solves this problem.

###message_bus.h

The message bus system constists of the following structs:

```
typedef struct local_message_bus{
	uint32_t number_of_ARP_packets_notice;
	uint32_t number_of_ARP_packets_error;

	PACKET *p_ARP_packets_notice[ MESSAGE_BUS_MAX_NUMBER_OF_ARP_PACKETS_NOTICE ];
	PACKET *p_ARP_packets_error[ MESSAGE_BUS_MAX_NUMBER_OF_ARP_PACKETS_ERROR ];
} LOCAL_MESSAGE_BUS;

typedef struct message_bus_subscription{
	uint8_t ARP_notice;
	uint8_t ARP_error;

	LOCAL_MESSAGE_BUS *p_local_message_bus;
} MESSAGE_BUS_SUBSCRIPTION;

typedef struct message_bus_subscriptions{
	uint32_t number_of_message_bus_subsciptions;

	MESSAGE_BUS_SUBSCRIPTION *p_message_bus_subscriptions[ MESSAGE_BUS_MAX_NUMBER_OF_MESSAGE_BUS_SUBSRIPTIONS ];
} MESSAGE_BUS_SUBSCRIPTIONS;
```

LOCAL\_MESSAGE\_BUS is the struct containing all the items (now only packets..) that the bus can support. Each class, if needed, has a own LOCAL\_MESSAGE\_BUS where data is being pushed on. message_bus.c keeps track of all the subsriptions with the MESSAGE\_BUS\_SUBSCRIPTION**S** struct. Here all the MESSAGE\_BUS\_SUBSCRIPTION structs are stored containing the settings and the pointer to the users (in this seperate .c files) their LOCAL\_MESSAGE\_BUS. Below log.c is shown. log.c only listens and gets all the events from the message bus.

```
#include "log.h"

static LOCAL_MESSAGE_BUS *p_local_message_bus;

void init_log( void ){
	uint8_t ARP_notice = SUBSCRIBED;
	uint8_t ARP_error = SUBSCRIBED;

	p_local_message_bus = create_message_bus_subscription( ARP_notice, ARP_error );
}

void update_log( void ){
	PACKET *p_ARP_packets_error = get_ARP_error_from_message_bus( p_local_message_bus );
	PACKET *p_ARP_packets_notice = get_ARP_notice_from_message_bus( p_local_message_bus );

	if ( p_ARP_packets_error != NULL ){
		print_packet( p_ARP_packets_error );
		free_packet( p_ARP_packets_error );
	}

	if ( p_ARP_packets_notice != NULL ){
		print_packet( p_ARP_packets_notice );
		free_packet( p_ARP_packets_notice );
	}
}
```

As you can see first, during the initilisation of the program, log.c is subsribed to both ARP_notice and ARP_error.

```
p_local_message_bus = create_message_bus_subscription( ARP_notice, ARP_error );
```

This creates a MESSAGE\_BUS\_SUBSCRIPTION and adds it to the MESSAGE\_BUS\_SUBSCRIPTION**S** struct (note the extra S here!). Next using 

```
get_ARP_error_from_message_bus( p_local_message_bus );
get_ARP_notify_from_message_bus( p_local_message_bus );
```

PACKETs are being pulled from the bus. Each PACKET struct is being cloned, i.e., duplicated (also the data inside, not just the pointer), to prevent segmentation faults later on. Great care was put into preventing memory leaks. Finally, the log.c can just print the packets. Now we are going to take a look at a sample program that send data to the bus:

```
void init_DAI( void ){
	uint8_t ARP_notice = UNSUBSCRIBED;
	uint8_t ARP_error = UNSUBSCRIBED;

	p_local_message_bus = create_message_bus_subscription( ARP_notice, ARP_error );
}

...
send_ARP_notice_to_message_bus( p_packet );
...
send_ARP_error_to_message_bus( p_packet );
...
```

Here you can see DAI not subsribing to anything and only sending messages to the bus. However, note that a combination of the two can also be used.


###Modules
All modules must have the following interface:

```
PACKET_LIST *p_packet_list;

void init_MODULE void ){
	...
}

void update_MODULE void ){
	...
}

add_packet_to_MODULE( PACKET *p_packet ){
	...
}
```

PACKET_LIST is a struct that stores packages, PACKETs can be added, get, removed from the PACKET_LIST, this is clearly shown in the header of **packet_list.h**:

```
PACKET_LIST* malloc_packet_list( void );
uint32_t index_of_packet_in_packet_list( PACKET_LIST *p_packet_list, PACKET *p_packet );
void add_packet_to_packet_list( PACKET_LIST *p_packet_list, PACKET *p_packet );
PACKET* get_packet_from_packet_list( PACKET_LIST *p_packet_list, uint32_t index );
PACKET* remove_packet_from_packet_list( PACKET_LIST *p_packet_list, uint32_t index );
PACKET* remove_next_packet_from_packet_list( PACKET_LIST *p_packet_list );
```

The update function does all the hard work, i.e., checking if the CONFIGURATION settings are met, checking for faulty packets, etc, when a PACKET is added by using the add\_packet\_to\_MODULE only basic checking is done, e.g., has_ARP_header( p_packet ). Finally, the init function is ofcourse called once when the program starts. Here things like subscriptions and loading local CONFUGIRATION can be done. I decided to seperate things to make the code as clear as possible for you and me.

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
