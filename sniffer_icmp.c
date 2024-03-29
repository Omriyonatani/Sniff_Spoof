// #include "sniffer.h"
#include <pcap.h>
#include <stdio.h>
#include "pcap.h"

/* This function will be invoked by pcap for each captured packet.
We can process each packet inside the function. */
void got_packet(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet)
{
printf("Got a packet ICMP\n");
}



int main()
{
    //initialize variables.
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "ip proto icmp";
    bpf_u_int32 net;

    // Step 1: Open live pcap session on NIC with name eth3
    handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);

    // Step 2: Compile filter_exp into BPF psuedo-code
    pcap_compile(handle, &fp, filter_exp, 0, net);
    pcap_setfilter(handle, &fp);

    // Step 3: Capture packets
    pcap_loop(handle, -1, got_packet, NULL);

    //Close the handle
    pcap_close(handle);
    return 0;
}


// Note: don’t forget to add "-lpcap" to the compilation command.
// For example: gcc -o sniff sniff.c -lpcap
