#ifndef __COMMON_H__
#define __COMMON_H__

#include <pcap/pcap.h>
#include <stdio.h>
#include <time.h>
#include <errno.h>
#include <stdint.h>

/*
 * Defining basic constants and declaring functions.
 * */

#ifndef PCAP_OPENFLAG_PROMISCUOUS
#define PCAP_OPENFLAG_PROMISCUOUS 1
#endif

#define FG_NATIVE_CYGWIN 1

#define ETH_ADDR_LEN 6
#define IPV4_ADDR_LEN 4

#define MAX_CAP_LEN 1514

#define BUFLEN_ETH 18
#define BUFLEN_IP 16
#define MAX_DUMP_LEN 80
#define MAX_LINE_LEN 16
#define MAX_LINEBUF 256

#define PAUSE                                                                  \
    printf("Press any key to continue...");                                    \
    fgetc(stdin)

extern uint8_t myEthAddr[ETH_ADDR_LEN];
extern uint8_t myIPAddr[IPV4_ADDR_LEN];
extern uint8_t defaultGatewayIP[IPV4_ADDR_LEN];
extern uint8_t destEthAddr[ETH_ADDR_LEN];
extern uint8_t destIPAddr[IPV4_ADDR_LEN];

extern uint8_t ethAddrBuf[ETH_ADDR_LEN];
extern uint8_t ipAddrBuf[IPV4_ADDR_LEN];

typedef uint32_t ipAddr_t;
int readReady();
char *time2DecStr(time_t);
ipAddr_t my_inet_Addr(char *);
char *ip_AddrStr(unsigned char *, char *);
char *eth_MacAddr(const unsigned char *, char *);

void print_IP(unsigned char *, char *);
void print_Data(const unsigned char *, int);

#endif /* __COMMON_H__ */