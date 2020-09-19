// #include "sniffer.h"
#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include<ctype.h>
#include "pcap.h"

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6
/* ethernet headers are always exactly 14 bytes */
#define SIZE_ETHERNET 14


/* IP header */
struct sniff_ip {
	unsigned char ip_vhl;		/* version << 4 | header length >> 2 */
	unsigned char ip_tos;		/* type of service */
	unsigned short ip_len;		/* total length */
	unsigned short ip_id;		/* identification */
	unsigned short ip_off;		/* fragment offset field */
	#define IP_RF 0x8000		/* reserved fragment flag */
	#define IP_DF 0x4000		/* dont fragment flag */
	#define IP_MF 0x2000		/* more fragments flag */
	#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
	unsigned char ip_ttl;		/* time to live */
	unsigned char ip_p;		    /* protocol */
	unsigned short ip_sum;		/* checksum */
	struct in_addr ip_src,ip_dst; /* source and dest address */
};




/* Ethernet header */
struct sniff_ethernet {
	unsigned char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
	unsigned char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
	unsigned short ether_type; /* IP? ARP? RARP? etc */
};





/* TCP header */
typedef unsigned int tcp_seq;

struct sniff_tcp {
	unsigned short th_sport;	/* source port */
	unsigned short th_dport;	/* destination port */
	tcp_seq th_seq;		/* sequence number */
	tcp_seq th_ack;		/* acknowledgement number */
	unsigned char th_offx2;	/* data offset, rsvd */
	#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
	unsigned char th_flags;
	#define TH_FIN 0x01
	#define TH_SYN 0x02
	#define TH_RST 0x04
	#define TH_PUSH 0x08
	#define TH_ACK 0x10
	#define TH_URG 0x20
	#define TH_ECE 0x40
	#define TH_CWR 0x80
	#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	unsigned short th_win;		/* window */
	unsigned short th_sum;		/* checksum */
	unsigned short th_urp;		/* urgent pointer */
};




/* This function will be invoked by pcap for each captured packet.
We can process each packet inside the function. */
void got_packet(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet)
{
    printf("Got a packet Sniff\n");
	const struct sniff_ethernet *ethernet; 	/* The ethernet header */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
	const char *payload;                    /* Packet payload */

	unsigned int size_ip;
	unsigned int size_tcp;


    // ethernet = (struct sniff_ethernet*)(packet);
	// ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	// size_ip = (ip->ip_vhl) *4;

	// if (size_ip < 20) {
	// 	printf("   * Invalid IP header length: %u bytes\n", size_ip);
	// 	return;
	// }

	// tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	// size_tcp = TH_OFF(tcp)*4;

	// if (size_tcp < 20) {
	// 	printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
	// 	return;
	// }
    
	// payload = (unsigned char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

    struct sniff_ethernet *eth = (struct sniff_ethernet *)packet;
    if(ntohs(eth->ether_type)==0x800)
    {
        struct sniff_ip *ip = (struct sniff_ip *)(packet + sizeof(struct sniff_ethernet));
        
        printf("   From: %s\n", inet_ntoa(ip->ip_src));
        printf("   To: %s\n", inet_ntoa(ip->ip_dst));

        switch(ip->ip_p)
        {
            case IPPROTO_TCP:
                    printf(" Protocol TCP\n");
                    break;
            case IPPROTO_UDP:
                    printf(" Protocol UDP\n");
                    break;
            case IPPROTO_ICMP:
                    printf(" Protocol ICMP\n");
                    break;
            default:
                    printf(" Other Protocol\n");
                    break;
        }
    }
    return;
}

int main()
{
    //initialize variables.
    char *dec = NULL;           //capture device name
    pcap_t *handle;             
    char errbuf[PCAP_ERRBUF_SIZE];      
    struct bpf_program fp;              
    char filter_exp[] = "ip proto icmp";      
	//proto IP and (host 10.0.2.6 and 10.0.2.7)
    bpf_u_int32 mask;       // subnet mask        
    bpf_u_int32 net;        // ip     
    int num_packets = -1;   // to capture all the packets   

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
