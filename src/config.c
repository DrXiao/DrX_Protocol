#include <stdint.h>
#include "common.h"

uint8_t myEthAddr[ETH_ADDR_LEN] = {0x50, 0x5b, 0xc2, 0xd0, 0xfa, 0xc5};

uint8_t myIPAddr[IPV4_ADDR_LEN] = {192, 168, 1, 108};

uint8_t defaultGatewayIP[IPV4_ADDR_LEN] = {192, 168, 1, 1};

uint8_t destEthAddr[ETH_ADDR_LEN] = {0xdc, 0xa6, 0x32, 0xbb, 0x5b, 0xd8};

uint8_t destIPAddr[IPV4_ADDR_LEN] = {192, 168, 1, 110};

uint8_t ethAddrBuf[ETH_ADDR_LEN];

uint8_t ipAddrBuf[IPV4_ADDR_LEN];

/*
 * Ubuntu 20.04 :   ETH -   {0x50, 0x5b, 0xc2, 0xd0, 0xfa, 0xc5};
 *                  IP  -   {192, 168, 43, 108};
 * 
 * 
 * Raspberry Pi :   ETH -   {0xdc, 0xa6, 0x32, 0xbb, 0x5b, 0xd8};
 *                  IP  -   {192, 168, 1, 110};
 * 
 * */