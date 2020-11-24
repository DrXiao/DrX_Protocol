#include <stdint.h>
#include "common.h"

uint8_t myEthAddr[ETH_ADDR_LEN] = {0x50, 0x5b, 0xc2, 0xd0, 0xfa, 0xc5};

uint8_t myIPAddr[IPV4_ADDR_LEN] = {192, 168, 43, 106};

uint8_t defaultGatewayIP[IPV4_ADDR_LEN] = {192, 168, 43, 0};

uint8_t destEthAddr[ETH_ADDR_LEN];

uint8_t destIPAddr[IPV4_ADDR_LEN];