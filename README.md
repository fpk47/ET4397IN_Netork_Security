###How to run:
Run the run.sh script in the folder containing:

```c
gcc pcap_file.c packet_list.c wifi.c tools.c configuration.c 
message.c DAI.c log.c message_bus.c capture.c packet.c 
parser.c main.c -lpcap -o test.out
./test.out
```

```
PCAP_FILE* p_pcap_file = open_pcap_file( "blackboard_sample.pcap", TYPE_RADIO_TAP );
```

The sample from blackboard containing the 802.11 packets is used to show how the IPS works.

**TESTED TO WORK ON THE VM**

**DAI.c is not updated (commented out) in this release**

**QUESTIONS ARE BELOW SOME INTRODUCTION NEEDED...**

### WIFI.c

A few important things need to be told first:

```c
static uint32_t get_oldest_index_from_list( void );  
static void add_packet_to_list( PACKET *p_packet );  
static PACKET* get_packet_from_list( uint32_t index );
```
These function inside WIFI.c are used to write data in a cyclic array, i.e., the oldest data is removed for the newest to be inserted. These function will re-occur later on when anwsering the question 1 and 2. Function should speak for themselves.

```c
void init_WIFI( void );
void update_WIFI( void );
void add_packet_to_WIFI( PACKET *p_packet );
```

Wifi.c has again the same structure as DAI.c. Again can send messages to the message bus.

### message_bus.c/h

The message bus is extended in order to also receive WIFI NOTICE and WIFI ARP (wifi arp replay notice) packets.

### Packet.c/h Parser.c/h

Great changes happened here in order to make room for RADIO TAP packets. A Packet is either a RADIO TAP packet or a ETHERNET packet. This was somewhat difficult because some variable were little and some were big endian.. For RADIO TAP: Depending on various fields (to_DS, from_DS) data is read differently [[link](http://www.rfwireless-world.com/Articles/WLAN-MAC-layer-protocol.html)]. Depending on the RADIO TAP header length the MAC timestamp location is different (I found this out by acident, see code):

```c
static uint32_t parse_radio_tap_header( uint8_t *p_data, RADIO_TAP_HEADER *p_radio_tap_header, uint32_t current_index ){
	memcpy( &(p_radio_tap_header->length), &p_data[ current_index + 2 ], 2 );

	if ( p_radio_tap_header->length != 36 ){
		memcpy( &(p_radio_tap_header->time), &p_data[ current_index + 8 ], 8 );
	} else{ 
		memcpy( &(p_radio_tap_header->time), &p_data[ current_index + 16 ], 8 );
	}

	return current_index + get_radio_tap_header_size( p_radio_tap_header );
}
```

The function **print\_packet( PACKET \*p\_packet )** is extended to print RADIO_TAP packets. Some basic RADIO\_TAP\_TYPEs are parsed, but all can be detected using information from the following [[link](https://supportforums.cisco.com/document/52391/80211-frames-starter-guide-learn-wireless-sniffer-traces)]. However, in order to parse the type of the RADIO\_TAP packet some byteshifting was needed:

```
memcpy( &(p_radio_tap_header->type), &p_data[ temp_index ], 1 );

uint8_t temp = (p_radio_tap_header->type)&0x0F;
temp >>= 2;

(p_radio_tap_header->type) &= 0xF0;
(p_radio_tap_header->type) |= temp;
```

Only the first 4 bytes needed to be bitshifted 2 to the right. Next I wil show all the included toolset for RADIO\_TAP packets..

```
uint8_t is_radio_tap_packet( PACKET *p_packet );

uint32_t has_radio_tap_src_address( PACKET *p_packet );
uint32_t has_radio_tap_dst_address( PACKET *p_packet );
uint32_t has_radio_tap_BSSID( PACKET *p_packet );
uint32_t has_radio_tap_transmission_station_address( PACKET *p_packet );
uint32_t has_radio_tap_receiving_station_address( PACKET *p_packet );

uint8_t* get_radio_tap_src_address( PACKET *p_packet );
uint8_t* get_radio_tap_dst_address( PACKET *p_packet );
uint8_t* get_radio_tap_BSSID( PACKET *p_packet );
uint8_t* get_radio_tap_transmission_station_address( PACKET *p_packet );
uint8_t* get_radio_tap_receiving_station_address( PACKET *p_packet );
uint8_t get_radio_tap_to_DS( PACKET *p_packet );
uint8_t get_radio_tap_from_DS( PACKET *p_packet );
uint8_t get_radio_tap_type( PACKET *p_packet );
char* get_radio_tap_type_name( PACKET *p_packet );
uint32_t get_radio_tap_length( PACKET *p_packet );
uint64_t get_radio_tap_time( PACKET *p_packet );
....
```

Finally, it is also now possible to mark packets "used" in order to prevent them being processed twice in a list.


```
uint32_t is_used( PACKET *p_packet );
void set_used( PACKET *p_packet );
```

###PROJCET 3: Question 1 (see also WIFI.c)

A potential disassociation or deauthentication attack can be reconised by scanning for one the following scenarios:

1. If a client sends a disassociation frame and quickly after tries to connect probable something is wrong. If the client wanted to leave the network it would not have reconnected.. This is catched by the following code:

```c
// Find an (not yet used) client authentication frame
PACKET *p_client_authentication_packet = find_client_authentication();

while ( p_client_authentication_packet != NULL ){
	// Find match, i.e., authentication and disassociation from same source with time in between < 100 ms
	find_client_authentication_match( p_client_authentication_packet );
	p_client_authentication_packet = find_client_authentication();
}
```

for the source code of the function in de code fragment above see WIFI.c. Given the clear function names it should be quite easy to understand how this is done.

2. If a router sends a disassociation frame, it could be the case that the router has found an attacker and wants to protect you by forcing you to leave. Or an attacker is sending a disassociation frame to you. This is captured by the following code:

```c
// Find AP or attacker sending disassociation 
PACKET *p_temp_packet = find_AP_disassociation();
if ( p_temp_packet != NULL ){
	sprintf( text, "WIFI NOTICE: Found AP or attacker sending disassociation, MAC=%s", get_MAC_address_name( get_radio_tap_src_address( p_temp_packet ) ) );
	set_packet_text( p_temp_packet, text );
	send_WIFI_radio_tap_notice_to_message_bus( p_temp_packet );
}
```

```c
static PACKET* find_AP_disassociation(){
	for( int i = 0; i < LIST_SIZE; i++ ){
		PACKET *p_temp_packet = get_packet_from_list( i );

		if ( p_temp_packet != NULL ){
			if ( is_radio_tap_packet( p_temp_packet ) ){
				if ( get_radio_tap_type( p_temp_packet ) == TYPE_RADIO_TAP_DISASSOCIATION ){

					uint8_t to_DS = get_radio_tap_to_DS( p_temp_packet );
					uint8_t from_DS = get_radio_tap_from_DS( p_temp_packet );

					if ( !(to_DS == 1 && from_DS == 1) ){
						uint8_t *p_MAC = get_radio_tap_src_address( p_temp_packet );
						uint8_t *p_BSSID = get_radio_tap_BSSID( p_temp_packet );
						
						// If p_BSSID == p_MAC --> Must be from AP
						if ( compare_MAC( p_MAC, p_BSSID ) && !is_used( p_temp_packet ) ){
							// Set used, to prevent using the same packet in the future..
							set_used( p_temp_packet );
							return p_temp_packet;
						}
					}
				}
			}
		}
	}

	return NULL;
} 
```

For all the cases proper messages are send to the message bus. If you load the **blackboard\_sample.pcap** file some output is shown.

```
[INFO] log.c: p_WIFI_radio_tap_packet_notice
----PACKET (total size = 82, count = 5)----
    MESSAGE: WIFI NOTICE: Found AP or attacker sending disassociation, MAC=c4:6e:1f:10:15:cf
  UNIQUE_ID: 109
       TYPE: RADIO_TAP
  RADIO_TAP: length      --> 36
  RADIO_TAP: time        --> 2861419421
  RADIO_TAP: type        --> Disassociation
  RADIO_TAP: to_DS       --> 0
  RADIO_TAP: from_DS     --> 1
  RADIO_TAP: dst_address --> c0:bd:d1:f1:17:90
  RADIO_TAP: BSSID       --> c4:6e:1f:10:15:cf
  RADIO_TAP: src_address --> c4:6e:1f:10:15:cf
-----------------
```

###PROJCET 3: Question 2 (see also WIFI.c)

First of all I would like to say that it took a lot of effort: first I had to find another router, secondly I had to borrow someone else his laptop to perform the attack. Ok, lets continue:

I performed the attack using the handson on page 313. When the attack began I recieved a lot of RADIO_TAP DATA frames. (for all the types in my system see line 913 of packet.c). Thus, my solution is: 

If there are many RADIO_TAP DATA frames from a mac address behind each other, it could indicate a ARP replay attack. As a proof of concept I implemented the following. (Yes, It can be improved)

In a cyclic list (see introduction, i.e., a list where the oldest packet is replaced by a newest (if necesary)) I check if two RADIO_TAP DATA frames from the same source are closer than X ms apart. If so, I create a notice for the message bus.

```
static void detect_short_time_between_data_frames(){
	uint32_t limit = get_oldest_index_from_list();
	decrease_index( &limit );
	
	for ( uint32_t i = get_oldest_index_from_list(); i != limit; increase_index( &i ) ){
		uint32_t current_index = i;
		PACKET *p_current_data_packet = get_next_data_packet( &current_index, limit );

		uint32_t next_index = current_index;
		increase_index( &next_index );
		PACKET *p_next_data_packet = get_next_data_packet( &next_index, limit );

		if ( p_current_data_packet != NULL && p_next_data_packet != NULL && is_used( p_current_data_packet ) == FALSE ){
			set_used( p_current_data_packet );
			uint8_t type_1 = get_radio_tap_type( p_current_data_packet );
			uint8_t type_2 = get_radio_tap_type( p_next_data_packet );

			if ( type_1 == TYPE_RADIO_TAP_DATA && type_2 == TYPE_RADIO_TAP_DATA ){
				uint64_t time_current = get_radio_tap_time( p_current_data_packet );
				uint64_t time_next = get_radio_tap_time( p_next_data_packet );

				uint8_t *p_MAC_1;
				uint8_t *p_MAC_2;

				if ( has_radio_tap_src_address( p_current_data_packet ) ){ 
					p_MAC_1 = get_radio_tap_src_address( p_current_data_packet ); 
				}	

				if ( has_radio_tap_transmission_station_address( p_current_data_packet ) ){ 
					p_MAC_1 = get_radio_tap_transmission_station_address( p_current_data_packet ); 
				}	

				if ( has_radio_tap_src_address( p_next_data_packet ) ){ 
					p_MAC_2 = get_radio_tap_src_address( p_next_data_packet ); 
				}	

				if ( has_radio_tap_transmission_station_address( p_next_data_packet ) ){
					p_MAC_2 = get_radio_tap_transmission_station_address( p_next_data_packet ); 
				}	

				if ( compare_MAC( p_MAC_1, get_MAC_broadcast() ) == FALSE ){
					if ( compare_MAC( p_MAC_1, p_MAC_2 ) ){
						uint64_t diff = (time_next - time_current) / 1000;
	
						if ( diff < 50 ){
							sprintf( text, "WIFI ARP REPLAY NOTICE: %llums between data frame and data frame of %s", diff, get_MAC_address_name( p_MAC_1 ) );
							set_packet_text( p_current_data_packet, text );
							set_packet_text( p_next_data_packet, text );
							send_WIFI_ARP_notice_to_message_bus( p_current_data_packet );
							send_WIFI_ARP_notice_to_message_bus( p_next_data_packet );
						}
					}
				}
			}
		}
	}
}
```

If you load the **blackboard\_sample.pcap** file some output is shown.

```
[INFO] log.c: p_WIFI_radio_tap_packet_notice
----PACKET (total size = 82, count = 8)----
    MESSAGE: WIFI NOTICE: Found AP or attacker sending disassociation, MAC=c4:6e:1f:10:15:cf
  UNIQUE_ID: 126
       TYPE: RADIO_TAP
  RADIO_TAP: length      --> 36
  RADIO_TAP: time        --> 2884835325
  RADIO_TAP: type        --> Disassociation
  RADIO_TAP: to_DS       --> 0
  RADIO_TAP: from_DS     --> 1
  RADIO_TAP: dst_address --> c0:bd:d1:f1:17:90
  RADIO_TAP: BSSID       --> c4:6e:1f:10:15:cf
  RADIO_TAP: src_address --> c4:6e:1f:10:15:cf
-----------------
[INFO] log.c: p_WIFI_ARP_packet_notice
----PACKET (total size = 199, count = 9)----
    MESSAGE: WIFI ARP REPLAY NOTICE: 5ms between data frame and data frame of c0:bd:d1:f1:17:90
  UNIQUE_ID: 120
       TYPE: RADIO_TAP
  RADIO_TAP: length      --> 36
  RADIO_TAP: time        --> 2881648385
  RADIO_TAP: type        --> Data
  RADIO_TAP: to_DS       --> 0
  RADIO_TAP: from_DS     --> 0
  RADIO_TAP: dst_address --> c4:6e:1f:10:15:cf
  RADIO_TAP: src_address --> c0:bd:d1:f1:17:90
  RADIO_TAP: BSSID       --> c4:6e:1f:10:15:cf
-----------------
```

###PROJCET 3: Question 3

In the netherlands, you are free to do with the 2.4Ghz and 5Ghz band as you please, but there are a couple of restrictions: it is not allowed to send with more then 100mW. Also, it is not allowed to send continiously, i.e., give others no time to also send. Finally, disrupting other networks is also not allowed [[link](https://www.antennebureau.nl/actueel/nieuwsbrieven/nieuwsbrief-wifi/wet-en-regelgeving-wifi)]. 

Knowing this, you are not allowed to willlfully interfere with a third party. If you have a licence, you are allowed to send with more then 100mW. As far as I could find, there are no other laws that state that you can jam other signals for defensive purposes.

If the only network security measure is boosting your own signal to prevent others from interfering, you should probably need to take more actions. Do you really need to use Wi-Fi? Do you change your Wi-Fi password on a regular basis, etc..

But, if the possible fine of interfering with other networks can be payed, if detected, and it is worth it. You could consider braking the law for your company's security.. 

###PROJCET 3: Question 4

The GTK is distributed to all the clients connected to the AP. If somehow an attacker could join the network (he knows the PMK), he could use the 4-way handshake to obtain the GTK to send messages to all the clients acting as of he is the AP. This goes against the assumption that only the AP may use the GTK to encode broadcast messages to all the clients. So if a client receives a broadcast message from the AP, he cannot be certain.

Also, if the attacker still has the PMK, capturing the 4-way handshake of some other client connecting, he could obtain that PTK and pretending to be de AP sending messages directly to that client. So if a client receives a unicast message from the AP, he cannot be certain.

Do note that you need to have the key, i.e., PMK, in order to perform this kind of attack.

###PROJCET 2: Question 1 (see also DAI.c)

####Notice 1: (ARP\_SRC\_MAC != ETH\_SRC\_MAC):

```c
uint32_t same_MAC = compare_MAC( get_ethernet_MAC_src( p_packet ), get_ARP_MAC_src( p_packet ) );
if( !same_MAC ){
	set_packet_text( p_packet, "DAI NOTICE: ARP_MAC != ETH_MAC" );
	send_ARP_notice_to_message_bus( p_packet );
} 
```

You send a ARP\_REQEUST to IP4="x" and recieve and ARP\_REPLY with ARP\_SRC\_MAC != ETH\_SRC\_MAC. You are now not sure if the sender is who he says he is, but it could still be a legit ARP\_REPLY.

You receive a ARP\_REQEUST with ARP\_SRC\_MAC != ETH\_SRC\_MAC. You are now not sure if the sender is who he says he is, but it could still be a legit ARP\_REQEUST.

####Notice 2: (NOTICE: ARP REQUEST NOT TO BROADCAST, I.E., ETH\_MAC\_DST != ff:ff:ff:ff:ff:ff):

```c
same_MAC = compare_MAC( get_ethernet_MAC_dst( p_packet ), get_MAC_broadcast() );
if( !same_MAC ){
	set_packet_text( p_packet, "DAI NOTICE: ARP REQUEST NOT TO BROADCAST" );
	send_ARP_notice_to_message_bus( p_packet );
} 
```

Some implementations require that an ARP\_REQEUST should be send to ethernet broadcast address. This is an notice because it could an indication of a directed WRONG ARP\_REQEUST. When an ARP\_REQEUST is send to the broadcast address all the hosts know it and it will be harder to spoof a single host in the network.

#### Notice 4: ARP REPLY NOT TO UNICAST, I.E., ETH\_MAC\_DST == ff:ff:ff:ff:ff:ff

```c
uint32_t same_MAC = compare_MAC( get_ethernet_MAC_dst( p_packet ), get_MAC_broadcast() );
if( same_MAC ){
	set_packet_text( p_packet, "DAI NOTICE: ARP REPLY NOT TO UNICAST" );
	send_ARP_notice_to_message_bus( p_packet );
}
```

According to the assignment, some devices apply this rule, and some do not. Therefore, it is necessary to make a notice so that a system administrator can take proper action.

####Error 1: MAC, IP4 pair in ARP\_REPLY not in configuration

```c
uint32_t index = index_of_ARP_entry_in_configuration( get_global_configuration(), get_ARP_MAC_src( p_packet ), get_ARP_IP4_src( p_packet ) );
if ( index == -1 ){ // NO EXISITING RECORD --> REJECT
	set_packet_text( p_packet, "DAI ERROR: { IP4, MAC } pair NOT IN LIST" );
	send_ARP_error_to_message_bus( p_packet );
}
```

This could mean that an attacker, who is not certified to join the network, gets acces to it. This approach is a little bit weird since it defeates the whole purpose of ARP. This code could be changed quickly to block certain attackers from joining. (Although this will only be effective when he/she is not changing his/her MAC-address). See the code below for the ohter approach:

```c
uint32_t index = index_of_ARP_entry_in_configuration( get_global_configuration(), get_ARP_MAC_src( p_packet ), get_ARP_IP4_src( p_packet ) );
if ( index != -1 ){ // NO EXISITING RECORD --> REJECT
	set_packet_text( p_packet, "DAI ERROR: { IP4, MAC } pair IN LIST" );
	send_ARP_error_to_message_bus( p_packet );
}
```

#### Error 2: BIND TO BROADCAST

```c
same_MAC = compare_MAC( get_ARP_MAC_dst( p_packet ), get_MAC_broadcast() );
if( same_MAC ){
	set_packet_text( p_packet, "DAI ERROR: BIND TO BROADCAST" );
	send_ARP_error_to_message_bus( p_packet );
}
```

This is straight forward: ff:ff:ff:ff:ff:ff is used for broadcasting ethernet frames in the network and can therefore not be "claimed" by an host.

###PROJCET 2: Question 2

A file is included, arp2.pcap that contains a lot of packets captured using the eduroam network. Note that not all notice and warning occur. In this document everything is explained: how does the configurations work, how does the message bus work, etc. 

###PROJCET 2: Question 3

Lets say H1 get's a ARP/_REPLY from H4 after sending a ARP/_REQUEST to the broadcast address requesting the MAC IP pair for the IP address of H4. But now H1 gets a lot of ARP packets from H2 requesting the MAC IP pair of H2. Now clearly something is wrong in the network, i.e., not everybody has the same state. To detect this I used the following code:

```c
if ( is_ARP_request( p_packet ) ){
	uint32_t count_1 = check_IP4_pair( get_ARP_IP4_src( p_packet ), get_ARP_IP4_dst( p_packet ) );
	if ( !compare_IP4( get_ARP_IP4_src( p_packet ), get_own_IP4() ) ){
		uint32_t count_2 = get_IP4_pair_count( get_own_IP4(), get_ARP_IP4_dst( p_packet ) );
	
		// If PAIR { OWN_IP, REMOTE_IP } occurs less then { CURRENT_IP, REMOTE_IP }
		if ( count_1 - count_2 > 3 ){
			sprintf( text, "DAI NOTICE: INCONSISTENCY: %s probably has no ARP entry of %s", get_IP4_address_name( get_ARP_IP4_src( p_packet ) ), get_IP4_address_name( get_ARP_IP4_dst( p_packet ) ) );
			set_packet_text( p_packet, text );
			send_ARP_notice_to_message_bus( p_packet );
		}
	}
}
```

First DAI.c counts (using a locally stored list) how many times the MAC IP4 pair of the request is listed in the list. check\_IP4\_pair does, besides the counting, also adds 1 to the internal counter of that pair. (see DAI.c for the implementation. Next, if the source is not our IP4 address, i.e., we are not one sending the request, count how many times we have send the request. Not here that get\_IP4\_pair\_count is used, i.e., nothing is changend internally. Now, if the difference is greater then 3, i.e., some other host has send 3 more ARP/_REQUEST then you have a notice is created.

Note that when running the arp2.pcap file this notice occurs a lot. This is because your own IP4 address probably does not match the address of the packets in the file.

####Make sure to include the following files:

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
