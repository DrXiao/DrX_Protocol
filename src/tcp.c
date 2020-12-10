#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <stdint.h>

#include "common.h"
#include "tcp.h"
#include "xlocp.h"
#include "flag.h"

void tcpMainDecapsulation(uint8_t *data, int dataLen) {
    tcpHeader_t *tcpPktHdr;
    tcpPktHdr = (tcpHeader_t *)data;
    uint8_t *dataPart = data + GET_TCP_OFFSET(tcpPktHdr);
#if (DEBUG_TCP == 1)
    printf("|--- TCP Header ---|\n");
    printf("Source Port - %d\n", swap16(tcpPktHdr->srcPort));
    printf("Destination Port - %d\n", swap16(tcpPktHdr->destPort));
    printf("Sequence Number - %u\n", swap32(tcpPktHdr->seqNumber));
    printf("Acknowledge Number - %u\n", swap32(tcpPktHdr->AckNumber));
    printf("Offset - %u\n", GET_TCP_OFFSET(tcpPktHdr));
    printf("Flag Code - %x\n", GET_TCP_FLAG(tcpPktHdr));
    printf("Window - %d\n", swap16(tcpPktHdr->window));
    printf("Checksum - %x\n", swap16(tcpPktHdr->checkSum));
    printf("Urgent Pointer - %x\n", tcpPktHdr->urgentPtr);
#endif
#if (DEBUG_XLOCP == 0)
    print_Data(dataPart, dataLen - GET_TCP_OFFSET(tcpPktHdr));
#else
    xlocpMainDecapsulation(dataPart, dataLen - 4 * GET_TCP_OFFSET(tcpPktHdr));
#endif
}

void tcpXlocpEncapsulation(tcpHeader_t *tcpHdr) {
    tcpHdr->srcPort = swap16(53234);
    tcpHdr->destPort = swap16(52234);
    tcpHdr->seqNumber = swap32(1);
    tcpHdr->offset_and_FlagCode = swap16(0x5000);
}