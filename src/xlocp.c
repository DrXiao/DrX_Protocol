#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include "common.h"
#include "eth.h"
#include "ip.h"
#include "tcp.h"
#include "xlocp.h"
#include "flag.h"

void xlocpMainDecapsulation(uint8_t *data, int dataLen) {
    if (dataLen < 12) {
        printf("Data is too short.\n");
        return;
    }
    xlocpHeader_t *xlocpPktHdr;
    xlocpPktHdr = (xlocpHeader_t *)data;
    uint32_t *dataPart = (uint32_t *)data;

    xlocpExplain(data, dataLen);
    *(uint32_t *)ipAddrBuf = HASH_DEST_IP(xlocpPktHdr);
    if (!memcmp(ipAddrBuf, myIPAddr, sizeof(myIPAddr))) {
        printf("Not a xlocp packet.\n");
        return;
    }
}

void xlocpExplain(uint8_t *data, int dataLen) {
    xlocpHeader_t *xlocpHeader = (xlocpHeader_t *)data;
    printf("|--- XLOCP Header ---|\n");
    printf("Hash IP : ");
    print_IP(xlocpHeader->destIPHashAddr, "\n");
    printf("Hash code : %x\n", xlocpHeader->hashCode);
    printf("Data type : %x\n", xlocpHeader->dataType);
    printf("Data Length : %u\n", xlocpHeader->dataLen);
    printf("Padding Len : %u\n", xlocpHeader->paddingLen);
}

void xlocpMainEncapsulation(pcap_t *devAdapterHandler) {
    xlocpPacket_t packet;

    memcpy(packet.data, "Hello world it ", 16);

    packet.xlocpHeader.dataType = XLOCP_CHAR_TYPE;
    packet.xlocpHeader.paddingLen = 0;
    packet.xlocpHeader.dataLen = 16;

    memcpy(packet.xlocpHeader.destIPHashAddr, destIPAddr, IPV4_ADDR_LEN);
    packet.xlocpHeader.hashCode = rand();

    *(uint32_t *)(packet.xlocpHeader.destIPHashAddr) =
        HASH_DEST_IP((&packet.xlocpHeader));
    uint32_t *hashPtr = (uint32_t *)packet.data;
    for (int i = 0; i < (16 + 0) / 4; i++, hashPtr++) {
        *hashPtr = *hashPtr ^ packet.xlocpHeader.hashCode;
    }

    tcpXlocpEncapsulation(&packet.tcpHeader);
    ipXlocpEncapsulation(&packet.ipHeader, sizeof(packet.data) + sizeof(packet.tcpHeader));
    ethXlocpEncapsulation(&packet.ethHeader);

    if (pcap_sendpacket(devAdapterHandler, (uint8_t *)&packet, sizeof(packet)) != 0) {
        fprintf(stderr, "\narpRequest Error sending: %s\n",
                pcap_geterr(devAdapterHandler));
    }
}