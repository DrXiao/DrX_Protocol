#ifndef __IP_H__
#define __IP_H__

#include <stdint.h>

#include "common.h"

#define IP_PROTOCOL_TCP 0x06
#define IP_PROTOCOL_UDP 0x17

#define IP_VER_MASK 0xF0
#define IP_HDR_LEN_MASK 0x0F
#define IP_FLAG_MASK 0xE000
#define IP_OFFSET_MASK 0x1FFF

#define GET_IP_VER(ipHeader) (((ipHeader->verIP_and_HdrLen) & IP_VER_MASK) >> 4)
#define GET_IP_HDR_LEN(ipHeader) 4 * ((ipHeader->verIP_and_HdrLen) & IP_HDR_LEN_MASK)
#define GET_IP_FLAG(ipHeader)                                                  \
    (((ipHeader->flag_and_Offset) & IP_FLAG_MASK) >> 13)
#define GET_IP_OFFSET(ipHeader) ((ipHeader->flag_and_Offset) & IP_OFFSET_MASK)

/*
 * Network Layer
 * IP packet - Header structure.
 *
 * 0    4    8         16   19    24        31 (bit)
 * |--------------------|--------------------|
 * |Ver | Len|   Type   |   Total Length     |
 * |--------------------|--------------------|
 * |   identification   |Flag|    Offset     |
 * |--------------------|--------------------|
 * |Time Live| protocol |  Header checksum   |
 * |--------------------|--------------------|
 * |            Source IP Address            |
 * |--------------------|--------------------|
 * |          Destination IP Address         |
 * |--------------------|--------------------|
 * |                Data ...                 |
 * |--------------------|--------------------|
 *
 * */

typedef struct {
    uint8_t verIP_and_HdrLen;
    uint8_t typeOfService;
    uint16_t totalLength;           // Needs swap16
    uint16_t ident;
    uint16_t flag_and_Offset;
    uint8_t timeToLive;
    uint8_t protocol;
    uint16_t checkSum;              // Needs swap16
    uint8_t srcIPAddr[IPV4_ADDR_LEN];
    uint8_t destIPAddr[IPV4_ADDR_LEN];
} ipHeader_t;

void ipMainDecapsulation(uint8_t *, int);

void ipXlocpEncapsulation(ipHeader_t *, int);

#endif /* __IP_H__ */