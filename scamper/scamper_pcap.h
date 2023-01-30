#pragma once
#include <pcap.h>

typedef struct scamper_pcap
{
    int      fd;
    pcap_t   *pcap;
} scamper_pcap_t;

