#ifndef __UDP_H__
#define __UDP_H__

#include <stdint.h>

#include "common.h"

/*
 * Transport Layer
 * User Datagram Protocol - Header structure.
 *
 * 0         8         16         24        31 (bit)
 * |--------------------|--------------------|
 * |     Source Port    |  Destination Port  |
 * |--------------------|--------------------|
 * |     Data length    |     Checksum       |
 * |--------------------|--------------------|
 * |                Data ...                 |
 * |--------------------|--------------------|
 *
 * */

typedef struct {
    uint16_t srcPort;
    uint16_t destPort;
    uint16_t lengthOfData;
    uint16_t checkSum;
} udpHeader_t;

void udpMainDecapsulation(uint8_t *, int);

#endif /* __UDP_H__ */