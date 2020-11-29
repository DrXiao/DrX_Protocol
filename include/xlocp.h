#ifndef __XLOCP_H__
#define __XLOCP_H__

#include <stdint.h>

#include "common.h"
#include "eth.h"
#include "ip.h"
#include "tcp.h"

/*
 * Dr.Xiao (Dr.Siao) - Learning-Oriented and Control Protocol - XLOCP (or SLOCP)
 *
 * For XLOCP, it defines a new protocol for the application layer of TCP/IP
 * Protocol.
 *
 * The user utilizing XLOCP must obey the following rules.
 *
 * 1.   For the original data, it needs to add a header, which is
 *      a new type of header and defined by XLOCP.
 *
 * 2.   After adding XLOCP header, user has to use...
 *
 *      A. 'TCP' protocol at tansport layer. (Adding TCP header.)
 *      B. 'IP' protocol at network layer. (IP header.)
 *      C. 'Ethernet II' at link layer. (Ethernet II Frame.)
 *
 *      Because XLOCP is at experiment phase, Obeying the above rules is in
 *      order to simply the problems while sending packets.
 *
 *      Actually, user has to deal with more details at every layer and the
 * details will be mentioned after.
 *
 * 3.   XLOCP - Header structure.
 *
 *  0         8         16         24        31 (bit)
 *  |--------------------|--------------------|
 *  |       Hash Destination IP Address       |
 *  |--------------------|--------------------|
 *  |            4 Byte Hash Code             |
 *  |--------------------|--------------------|
 *  | DataType|PaddingLen|    Data Length     |
 *  |--------------------|--------------------|
 *  |                Data (hash) ...          |
 *  |--------------------|--------------------|
 *  |                   ...                   |
 *  |--------------------|--------------------|
 *  |                (Padding)                |
 *  |--------------------|--------------------|
 *
 * 4. For "Data Type" field, the data should be explained as
 *          0x01 - unsigned char            *
 *          0x02 - unsigned short
 *          0x03 - unsigned int             *
 *          0x04 - unsigned long long int
 *          0x05 - unsigned float           
 *          0x06 - unsigned double          
 *          0x83 - signed int               *
 *          0x85 - signed float             *
 *          0x86 - signed double            *
 *
 * */

#define XLOCP_CHAR_TYPE 0x01
#define XLOCP_UINT_TYPE 0x03
#define XLOCP_INT 0x83
#define XLOCP_FLOAT 0x85
#define XLOCP_DOUBLE 0x86

#define HASH_DEST_IP(xlocpHeader)                                              \
    (*(uint32_t *)(xlocpHeader->destIPHashAddr) ^ xlocpHeader->hashCode)

typedef struct {
    uint8_t destIPHashAddr[IPV4_ADDR_LEN];
    uint32_t hashCode;
    uint8_t dataType;
    uint8_t paddingLen;
    uint16_t dataLen;
} xlocpHeader_t;

typedef struct {
    ethHeader_t ethHeader;
    ipHeader_t ipHeader;
    tcpHeader_t tcpHeader;
    xlocpHeader_t xlocpHeader;
    uint8_t data[1514 - sizeof(xlocpHeader_t) - sizeof(tcpHeader_t) -
                 sizeof(ipHeader_t) - sizeof(ethHeader_t)];
} xlocpPacket_t;

void xlocpMainDecapsulation(uint8_t *, int);

void xlocpMainEncapsulation(pcap_t *);

void xlocpExplain(uint8_t *, int);

#endif