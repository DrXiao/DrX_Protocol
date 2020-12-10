#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <stdint.h>
#include <string.h>

#include "common.h"
#include "eth.h"
#include "ip.h"
#include "arp.h"
#include "flag.h"

void ethMainDecapsulation(uint8_t *data, int dataLen) {
    ethPacket_t *ethPkt;
    ethPkt = (ethPacket_t *)data;
#if (DEBUG_ETH == 1)
    printf("|--- Ethernet Header ---|\n");
    printf("Dest Mac - %s\n", eth_MacAddr(ethPkt->ethHeader.destEthAddr, NULL));
    printf("Src Mac - %s\n", eth_MacAddr(ethPkt->ethHeader.srcEthAddr, NULL));
    printf("Eth Type - 0x%.4x\n", swap16(ethPkt->ethHeader.ethType));
#endif /* DEBUG_ETH */

    switch (swap16(ethPkt->ethHeader.ethType)) {
    case ETH_TYPE_IP: ipMainDecapsulation(ethPkt->data, dataLen - sizeof(ethHeader_t)); break;
    case ETH_TYPE_ARP: break;
    }
}

void ethXlocpEncapsulation(ethHeader_t *ethHdr) {
    memcpy(ethHdr->srcEthAddr, myEthAddr, ETH_ADDR_LEN);
    memcpy(ethHdr->destEthAddr, destEthAddr,ETH_ADDR_LEN);
    ethHdr->ethType = swap16(ETH_IP);
}