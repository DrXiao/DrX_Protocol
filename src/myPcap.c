#include <pcap/pcap.h>
#include "myPcap.h"
#include "common.h"
#include "eth.h"
#include "flag.h"

char *myPcap_GetDevice(int defn, pcap_if_t **allDevs) {
    pcap_if_t *devPtr;

    int selectDevNum, numbersOfDevs = 0;
    char errbuf[PCAP_ERRBUF_SIZE];
    char buf[MAX_LINEBUF];

    if (pcap_findalldevs(allDevs, errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        *allDevs = NULL;
        return NULL;
    }

    if (defn > 0) {
        selectDevNum = defn;
        for (devPtr = *allDevs; devPtr; devPtr = devPtr->next, ++numbersOfDevs)
            ;
    }
    else {
        printf("Device list : \n");

        for (devPtr = *allDevs; devPtr; devPtr = devPtr->next) {
            printf("%2d. %-20s\n    ", ++numbersOfDevs, devPtr->name);
            if (devPtr->description)
                printf(" (%s)\n", devPtr->description);
            else
                printf(" (No description available)\n");
        }
        if (numbersOfDevs == 0) {
            fprintf(stderr, "No interfaces found!");
            return NULL;
        }

        printf("Enter the interface number (1-%d) : \n", numbersOfDevs);
        fgets(buf, MAX_LINEBUF, stdin);
        sscanf(buf, "%d", &selectDevNum);
    }
    if (selectDevNum > numbersOfDevs || selectDevNum < 1) {
        printf("\nInterface number out of range.\n");

        pcap_freealldevs(*allDevs);
        *allDevs = NULL;
        return NULL;
    }

    for (devPtr = *allDevs, numbersOfDevs = 0; numbersOfDevs < selectDevNum - 1;
         devPtr = devPtr->next, numbersOfDevs++)
        ;

    printf("device : %s\n", devPtr->name);
    return devPtr->name;
}

int mainProc(pcap_t *devAdapterHandler) {
    struct pcap_pkthdr *packetHeader;
    const u_char *packetData;
    int responseValue, key, packetLen;

#if (DEBUG_PHYSICAL == 1)
    char timeStr[16];
    struct tm localTime;
#endif /* DEBUG_PHYSICAL */

    while ((responseValue = pcap_next_ex(devAdapterHandler, &packetHeader,
                                         &packetData)) >= 0) {

        if (responseValue > 0) {

            packetLen = packetHeader->caplen;
            printf("<<< Packet  Start >>>\n");
#if (DEBUG_PHYSICAL == 1)
            printf("|--- Physical Header ---|\n");
            localtime_r(&packetHeader->ts.tv_sec, &localTime);
            strftime(timeStr, sizeof(timeStr), "%H:%M:%S", &localTime);
            printf("%s, %.6ld ,len:%d\n", timeStr, packetHeader->ts.tv_usec,
                   packetHeader->len);
#endif /* DEBUG_PHYSICAL */

            ethMainDecapsulation((uint8_t *)packetData, packetLen);

            printf("<<< Packet  End >>>\n\n");

            if (!readReady()) continue;
            if ((key = fgetc(stdin)) == '\n') break;
            ungetc(key, stdin);
        }
    }

    if (responseValue == -1) {
        fprintf(stderr, "Error reading the packets: %s\n",
                pcap_geterr(devAdapterHandler));
        return -1;
    }

    return 0;
}
