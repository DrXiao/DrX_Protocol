#ifndef __TCP_H__
#define __TCP_H__

#include <stdint.h>

#include "common.h"

#define TCP_OFFSET_MASK 0xF000
#define TCP_FLAG_CODE_MASK 0x003F

#define GET_TCP_OFFSET(tcpHeader)                                              \
    ((((swap16(tcpHeader->offset_and_FlagCode)) & TCP_OFFSET_MASK) >> 12) << 2)
#define GET_TCP_FLAG(tcpHeader)                                                \
    (((swap16(tcpHeader->offset_and_FlagCode)) & TCP_FLAG_CODE_MASK))

/*
 *  Transport Layer
 *  Transmission Control Protocol - Header structure.
 *
 *  0     4    8  10    16         24        31 (bit)
 *  |--------------------|--------------------|
 *  |     Source Port    |  Destination Port  |
 *  |--------------------|--------------------|
 *  |              Sequence Number            |
 *  |--------------------|--------------------|
 *  |           Acknowledge Number            |
 *  |--------------------|--------------------|
 *  |Offset| *No* | Flag |      Window        |
 *  |--------------------|--------------------|
 *  |       Checksum     |   Urgent Pointer   |
 *  |--------------------|--------------------|
 *  |                  Data ...               |
 *  |--------------------|--------------------|
 *
 *  *No* : Reserved (No any use).
 * */

typedef struct {
    uint16_t srcPort;       // Needs swap16
    uint16_t destPort;      // Needs swap16
    uint32_t seqNumber;
    uint32_t AckNumber;
    uint16_t offset_and_FlagCode;   // Needs swap16
    uint16_t window;
    uint16_t checkSum;
    uint16_t urgentPtr;
} tcpHeader_t;

void tcpMainDecapsulation(uint8_t *, int);

#endif /* __TCP_H__ */