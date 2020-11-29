#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <pcap/pcap.h>

#include "myPcap.h"
#include "common.h"
#include "xlocp.h"

xlocpPacket_t pkt;

#ifndef PCAP_OPENFLAG_PROMISCUOUS
#define PCAP_OPENFLAG_PROMISCUOUS 1
#endif

int main(int argc, char **argv) {
    srand(time(NULL));
    pcap_if_t *allDevs;
    char *devName, errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *devAdapterHandler;

    if (argc == 2)
        devName = argv[1];
    else if ((devName = myPcap_GetDevice(0, &allDevs)) == NULL)
        return -1;

    if ((devAdapterHandler =
             pcap_open_live(devName, MAX_CAP_LEN, PCAP_OPENFLAG_PROMISCUOUS,
                            100, errbuf)) == NULL) {
        fprintf(stderr, "\nError opening source: %s\n", errbuf);
        return -1;
    }

    /* Starting */

    mainProc(devAdapterHandler);

    /* Ending */

    pcap_close(devAdapterHandler);

    if (allDevs) {
        printf("Cleaning the list with devices!!\n");
        pcap_freealldevs(allDevs);
    }

    PAUSE;
    return 0;
}