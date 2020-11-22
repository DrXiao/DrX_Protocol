#ifndef __MY_PCAP_H__
#define __MY_PCAP_H__

#include <pcap/pcap.h>

/*
 * Declaring my functions.
 * */

char *myPcap_GetDevice(int , pcap_if_t **);
int mainProc(pcap_t *);

#endif /* __MY_PCAP_H__ */