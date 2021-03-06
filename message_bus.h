#ifndef MESSAGE_BUS_H
#define MESSAGE_BUS_H

#include "general_includes.h"
#include "parser.h"
#include "packet.h"
#include "message.h"

#define MESSAGE_BUS_ARP_NOTICE 0x01
#define MESSAGE_BUS_ARP_ERROR 0x02

#define SUBSCRIBED TRUE
#define UNSUBSCRIBED FALSE

#define MESSAGE_BUS_MAX_NUMBER_OF_MESSAGE_BUS_SUBSRIPTIONS 100
#define MESSAGE_BUS_MAX_NUMBER_OF_ARP_PACKETS_NOTICE 100
#define MESSAGE_BUS_MAX_NUMBER_OF_ARP_PACKETS_ERROR 100
#define MESSAGE_BUS_MAX_NUMBER_OF_WIFI_RADIO_TAP_PACKETS_NOTICE 100
#define MESSAGE_BUS_MAX_NUMBER_OF_WIFI_ARP_PACKETS_NOTICE 100

typedef struct local_message_bus{
	uint32_t number_of_ARP_packets_notice;
	uint32_t number_of_ARP_packets_error;
	uint32_t number_of_WIFI_radio_tap_packets_notice;
	uint32_t number_of_WIFI_ARP_packets_notice;

	PACKET *p_ARP_packets_notice[ MESSAGE_BUS_MAX_NUMBER_OF_ARP_PACKETS_NOTICE ];
	PACKET *p_ARP_packets_error[ MESSAGE_BUS_MAX_NUMBER_OF_ARP_PACKETS_ERROR ];
	PACKET *p_WIFI_radio_tap_packets_notice[ MESSAGE_BUS_MAX_NUMBER_OF_WIFI_RADIO_TAP_PACKETS_NOTICE ];
	PACKET *p_WIFI_ARP_packets_notice[ MESSAGE_BUS_MAX_NUMBER_OF_WIFI_ARP_PACKETS_NOTICE ];
} LOCAL_MESSAGE_BUS;

typedef struct message_bus_subscription{
	uint8_t ARP_notice;
	uint8_t ARP_error;
	uint8_t WIFI_radio_tap_notice;
	uint8_t WIFI_ARP_notice;

	LOCAL_MESSAGE_BUS *p_local_message_bus;
} MESSAGE_BUS_SUBSCRIPTION;

typedef struct message_bus_subscriptions{
	uint32_t number_of_message_bus_subsciptions;

	MESSAGE_BUS_SUBSCRIPTION *p_message_bus_subscriptions[ MESSAGE_BUS_MAX_NUMBER_OF_MESSAGE_BUS_SUBSRIPTIONS ];
} MESSAGE_BUS_SUBSCRIPTIONS;

void init_message_bus( void );

void free_message_bus_subsription( MESSAGE_BUS_SUBSCRIPTION *p_message_bus_subscription );
void free_local_message_bus( LOCAL_MESSAGE_BUS *p_local_message_bus );

LOCAL_MESSAGE_BUS* create_message_bus_subscription( uint8_t ARP_notice, uint8_t ARP_error, uint8_t WIFI_radio_tap_notice, uint8_t WIFI_ARP_notice );

PACKET* get_ARP_notice_from_message_bus( LOCAL_MESSAGE_BUS *p_local_message_bus );
PACKET* get_ARP_error_from_message_bus( LOCAL_MESSAGE_BUS *p_local_message_bus );
PACKET* get_WIFI_radio_tap_notice_from_message_bus( LOCAL_MESSAGE_BUS *p_local_message_bus );
PACKET* get_WIFI_ARP_notice_from_message_bus( LOCAL_MESSAGE_BUS *p_local_message_bus );

void send_ARP_notice_to_message_bus( PACKET *p_ARP_packet_notice );
void send_ARP_error_to_message_bus( PACKET *p_ARP_packet_error );
void send_WIFI_radio_tap_notice_to_message_bus( PACKET *p_WIFI_radio_tap_packet_notice );
void send_WIFI_ARP_notice_to_message_bus( PACKET *p_WIFI_ARP_packet_notice );

#endif