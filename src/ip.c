#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <stdint.h>

#include "common.h"
#include "ip.h"
#include "tcp.h"
#include "udp.h"
#include "flag.h"

void ipMainDecapsulation(uint8_t *data, int dataLen) {
    ipHeader_t *ipPktHdr;

    ipPktHdr = (ipHeader_t *)data;
    uint8_t *dataPart = data + GET_IP_HDR_LEN(ipPktHdr);

#if (DEBUG_IP == 1)
    printf("|--- Protocol Header ---|\n");
    printf("Version - %.x\n", GET_IP_VER(ipPktHdr));
    printf("Header Len - %d\n", GET_IP_HDR_LEN(ipPktHdr));
    printf("Type of Service - %x\n", ipPktHdr->typeOfService);
    printf("Total Length - %d\n", swap16(ipPktHdr->totalLength));
    printf("Identification - %.x\n", ipPktHdr->ident);
    printf("Flag - %x\n", GET_IP_FLAG(ipPktHdr));
    printf("Offset - %d\n", GET_IP_OFFSET(ipPktHdr));
    printf("Time to Live - %d\n", ipPktHdr->timeToLive);
    printf("Protocol Type - %.4x\n", ipPktHdr->protocol);
    printf("Checksum - %x\n", swap16(ipPktHdr->checkSum));
    printf("Source IP - %s\n", ip_AddrStr(ipPktHdr->srcIPAddr, NULL));
    printf("Destination IP - %s\n", ip_AddrStr(ipPktHdr->destIPAddr, NULL));

#endif /* DEBUG_IP */
    switch (ipPktHdr->protocol) {
    case IP_PROTOCOL_TCP:
        tcpMainDecapsulation(dataPart, dataLen - GET_IP_HDR_LEN(ipPktHdr));
        break;
    case IP_PROTOCOL_UDP: break;
    }
}