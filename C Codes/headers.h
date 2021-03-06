#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#ifndef SIZE_ETHERNET
#define SIZE_ETHERNET 14
#endif
#define ETHER_ADDR_LEN 6
#define PCKT_LEN 1024


unsigned short checksum(unsigned short *buffer, int size)
{
    unsigned long cksum=0;
    while (size > 1)
    {
        cksum += *buffer++;
        size  -= sizeof(unsigned short);
    }
    if (size)
    {
        cksum += *(char*)buffer;
    }
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >>16);
    return (unsigned short)(~cksum);
}

/* Ethernet addresses are 6 bytes */
/* ethernet headers are always exactly 14 bytes  */

/* Ethernet header */
struct sniff_ethernet
{
	unsigned char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
	unsigned char ether_shost[ETHER_ADDR_LEN];	  /* Source host address */
	unsigned char ether_type;					   /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip
{
	unsigned ip_vhl;			   /* version << 4 | header length >> 2 */
	unsigned ip_tos;			   /* type of service */
	unsigned ip_len;			   /* total length */
	unsigned ip_id;				   /* identification */
	unsigned ip_off;			   /* fragment offset field */
#define IP_RF 0x8000			   /* reserved fragment flag */
#define IP_DF 0x4000			   /* dont fragment flag */
#define IP_MF 0x2000			   /* more fragments flag */
#define IP_OFFMASK 0x1fff		   /* mask for fragmenting bits */
	unsigned ip_ttl;			   /* time to live */
	unsigned ip_p;				   /* protocol */
	unsigned short ip_sum;		   /* checksum */
	struct in_addr ip_src, ip_dst; /* source and dest address */
};
#define IP_V(ip) (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef unsigned int tcp_seq;

struct sniff_tcp {
	unsigned short th_sport; /* source port */
	unsigned short th_dport; /* destination port */
	tcp_seq th_seq;			 /* sequence number */
	tcp_seq th_ack;			 /* acknowledgement number */
	unsigned char th_offx2;  /* data offset, rsvd */
    #define TH_OFF(th)  (((th)->th_offx2 & 0xf0) >> 4)
	unsigned char th_flags;
	#define TH_FIN 0x01
	#define TH_SYN 0x02
	#define TH_RST 0x04
	#define TH_PUSH 0x08
	#define TH_ACK 0x10
	#define TH_URG 0x20
	#define TH_ECE 0x40
	#define TH_CWR 0x80
	#define TH_FLAGS (TH_FIN | TH_SYN | TH_RST | TH_ACK | TH_URG | TH_ECE | TH_CWR)
	unsigned short th_win; /* window */
	unsigned short th_sum; /* checksum */
	unsigned short th_urp; /* urgent pointer */
};

struct sniff_icmp{
	#define ICMP_ECHO_REQ 8
	#define ICMP_ECHO_RES 0
	#define ICMP_HDR_LEN 4
 	unsigned char icmp_type;
 	unsigned char icmp_code;
 	unsigned short icmp_cksum;		/* icmp checksum */
 	unsigned short icmp_id;				/* icmp identifier */
 	unsigned short icmp_seq;			/* icmp sequence number */
};

#define DATALEN (PCKT_LEN - sizeof(struct sniff_icmp) - sizeof(struct sniff_ip))

struct icmp_pckt{
	struct sniff_ip ip_hdr;
	struct sniff_icmp icmp_hdr;
	char echoData[DATALEN];
} icmp_packet;

typedef struct icmp_pckt ICMP_Packet;
