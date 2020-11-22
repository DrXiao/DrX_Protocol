#ifndef __ICMP_H__
#define __ICMP_H__

#include <stdint.h>

#include "common.h"

/*
 * Network Layer
 * Internet Control Message Protocol - Header structure.
 *
 * 0         8         16         24        31 (bit)
 * |--------------------|--------------------|
 * | MsgType |   Code   |      Checksum      |
 * |--------------------|--------------------|
 * |            Message Description          |
 * |--------------------|--------------------|
 * |                Data ...                 |
 * |--------------------|--------------------|
 *
 * */

typedef struct {
    uint8_t msgType;
    uint8_t code;
    uint16_t checksum;
    uint32_t msgDescription;
} icmpHeader;

void icmpMainDecapsulation(uint8_t *, int);

#endif /* __ICMP_H__ */