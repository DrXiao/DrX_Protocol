#ifndef __ARP_H__
#define __ARP_H__

#include <stdint.h>

#include "common.h"

/*
 * Assigned Numbers and Parameters
 *
 * Because the domain of network uses 'big-endian' usually
 * and C language is 'little-endian', In order to cooperate
 * with network, we need to use 'big-endian' when writing the
 * parts related to network.
 *
 * For example, ethernet type :
 *      1. 0x08 00 : represents IPv4.
 *      2. 0x08 06 : represents ARP.
 *
 * We have to use reverse order to record them.
 * so,
 *      0x08 00 -> 0x00 08
 *      0x08 06 -> 0x06 08
 * */

#define ETH_IP 0x0008
#define ETH_ARP 0x0608

/*
 *  Network layer
 *  Address Resolution Protocol - Packet Structure
 *
 *  0         8         16         24        31 (bit)
 *  |--------------------|--------------------|
 *  |  Ethernet Type     |  Protocol Type     |
 *  |--------------------|--------------------|
 *  |  ethLen |  ipLen   |  Operation Type    |
 *  |--------------------|--------------------|
 *  |  Source Ethernet Address (0~3 Byte)     |
 *  |--------------------|--------------------|
 *  |  srcEthAddr  (4~5) |  Src IP Addr (0~1) |
 *  |--------------------|--------------------|
 *  |  Src IP Addr (2~3) |  destEthAddr (0~1) |
 *  |--------------------|--------------------|
 *  |  Destination Ethernet Address  (2~5)    |
 *  |--------------------|--------------------|
 *  |  Destination IP Address (0~3 Byte)      |
 *  |--------------------|--------------------|
 *
 * Using a structure called myArp_t to represent
 * the above data.
 * */

typedef struct {
    uint16_t ethType;
    uint16_t ipType;
    uint8_t ethLen;
    uint8_t ipLen;
    uint16_t op;
    uint8_t srcEthAddr[ETH_ADDR_LEN];
    uint8_t srcIPAddr[IPV4_ADDR_LEN];
    uint8_t destEthAddr[ETH_ADDR_LEN];
    uint8_t destIPAddr[IPV4_ADDR_LEN];
} arpHeader_t;

void arpMainDecapsulation(uint8_t *, int);

#endif /* __ARP_H__ */