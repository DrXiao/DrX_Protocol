#ifndef __ETH_H__
#define __ETH_H__

#include <pcap/pcap.h>
#include <stdint.h>

#include "common.h"

/*
 * Link layer
 * The structure of Ethernet Frame
 *
 * 0         8         16         24        31 (bit)
 * |--------------------|--------------------|
 * |    Destination MAC Address (0~3 Byte)   |
 * |--------------------|--------------------|
 * |  DestMACAddr (4~5) |  SrcMACAddr (0~1)  |
 * |--------------------|--------------------|
 * |       Source MAC Address (2~5 Byte)     |
 * |--------------------|--------------------|
 * |    Ethernet Type   |   Payload  (data)  |
 * |--------------------|--------------------|
 * |                Payload (data)...        |
 * |--------------------|--------------------|
 *
 *  Ethernet type : 
 *          0x0800 : IPv4
 *          0x0806 : ARP
 * 
 * */

#define ETH_TYPE_IP 0x0008
#define ETH_TYPE_ARP 0x0608

typedef struct {
    uint8_t destEthAddr[ETH_ADDR_LEN];
    uint8_t srcEthAddr[ETH_ADDR_LEN];
    uint16_t ethType;   // Needs swap16
} ethHeader_t;

typedef struct {
    ethHeader_t ethHeader;
    uint8_t data[MAX_CAP_LEN];
} ethPacket_t;

void ethMainDecapsulation(uint8_t *, int);

#endif /* __ETH_H__ */