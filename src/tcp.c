#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <stdint.h>

#include "common.h"
#include "tcp.h"
#include "flag.h"

void tcpMainDecapsulation(uint8_t *data, int dataLen) {
    tcpHeader_t *tcpPktHdr;
    tcpPktHdr = (tcpHeader_t *)data;
    uint8_t *dataPart = data + GET_TCP_OFFSET(tcpPktHdr);
#if (DEBUG_TCP == 1)
    printf("|--- TCP Header ---|\n");
    printf("Source Port - %d\n", tcpPktHdr->srcPort);
    printf("Destination Port - %d\n", tcpPktHdr->destPort);
    printf("Sequence Number - %d\n", tcpPktHdr->seqNumber);
    printf("Acknowledge Number - %d\n", tcpPktHdr->AckNumber);
    printf("Offset - %d\n", GET_TCP_OFFSET(tcpPktHdr));
    printf("Flag Code - %x\n", GET_TCP_FLAG(tcpPktHdr));
    printf("Window - %d\n", tcpPktHdr->window);
    printf("Checksum - %x\n", tcpPktHdr->checkSum);
    printf("Urgent Pointer - %x\n", tcpPktHdr->urgentPtr);
#endif
    print_Data(dataPart, dataLen - 4 * GET_TCP_OFFSET(tcpPktHdr));
}