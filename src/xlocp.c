#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <stdint.h>
#include <string.h>

#include "common.h"
#include "xlocp.h"
#include "flag.h"

void xlocpMainDecapsulation(uint8_t *data, int dataLen) {
    if(dataLen < 12) {
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