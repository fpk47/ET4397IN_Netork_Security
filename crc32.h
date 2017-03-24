/* --------------------------------------------------------------------------

uint16_t calculateCRC16( uint8_t size, uint32_t crc, uint32_t polynomial, uint8_t *pData )
- [SLOW] CRC32 calculation for initialisation

Whole file authored by Frits Kastelein

-------------------------------------------------------------------------- */

#ifndef _CRC32_H__
#define _CRC32_H__

#include "general_includes.h"
#include "tools.h"

#define PACKET_POLYNOMIAL_SIZE sizeof(uint32_t)

uint32_t crc32(uint32_t crc, const void *buf, size_t size);

//uint32_t calculateCRC32( uint32_t size, uint32_t crc, uint32_t polynomial, uint8_t *pData );

#endif