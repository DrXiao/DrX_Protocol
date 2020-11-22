#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <stdint.h>

#include "common.h"
#include "eth.h"
#include "ip.h"
#include "arp.h"
#include "flag.h"

void ethMainDecapsulation(uint8_t *data, int dataLen) {
    ethPacket_t *ethPkt;
    ethPkt = (ethPacket_t *)data;
#if (DEBUG_ETH == 1)
    uint8_t ethType_LeftByte = *((uint8_t *)&ethPkt->ethHeader.ethType);
    uint8_t ethType_RightByte = *(((uint8_t *)&ethPkt->ethHeader.ethType) + 1);

    printf("|--- Ethernet Header ---|\n");
    printf("Dest Mac - %s\n", eth_MacAddr(ethPkt->ethHeader.destEthAddr, NULL));
    printf("Src Mac - %s\n", eth_MacAddr(ethPkt->ethHeader.srcEthAddr, NULL));
    printf("Eth Type - 0x%.2x%.2x\n", ethType_LeftByte, ethType_RightByte);
#endif /* DEBUG_ETH */

    switch (ethPkt->ethHeader.ethType) {
    case ETH_TYPE_IP: ipMainDecapsulation(ethPkt->data, dataLen); break;
    case ETH_TYPE_ARP: break;
    }
}