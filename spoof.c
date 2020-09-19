int sd;
struct sockaddr_in sin;
char buffer[1024]; // You can change the buffer size

/* Create a raw socket with IP protocol. The IPPROTO_RAW parameter
* tells the sytem that the IP header is already included;
* this prevents the OS from adding another IP header.
*/

sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
if(sd < 0) {
perror("socket() error"); exit(-1);
}



/* This data structure is needed when sending the packets
* using sockets. Normally, we need to fill out several
* fields, but for raw sockets, we only need to fill out
* this one field */
sin.sin_family = AF_INET;
// Here you can construct the IP packet using buffer[]
//


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


//


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


//
- fill in the data part if needed ...
// Note: you should pay attention to the network/host byte order.
/* Send out the IP packet.
* ip_len is the actual size of the packet. */


if(sendto(sd, buffer, ip_len, 0, (struct sockaddr *)&sin,
sizeof(sin)) < 0) {
perror("sendto() error"); exit(-1);
}
