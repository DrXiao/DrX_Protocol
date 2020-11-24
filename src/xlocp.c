#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <stdint.h>

#include "common.h"
#include "xlocp.h"
#include "flag.h"


void xlocpMainDecapsulation(uint8_t *data, int dataLen) {
    xlocpHeader_t *xlocpPktHdr;
    xlocpPktHdr = (xlocpHeader_t *)data;
    uint32_t *dataPart = (uint32_t *)data;

    

}