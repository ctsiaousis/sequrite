#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <signal.h>
#include <net/ethernet.h>
#include <netinet/ether.h> 
#include <netinet/ip6.h>
#include <netinet/tcp.h> 
#include <netinet/udp.h> 
#include <pcap.h>

#define clear() printf("\033[H\033[J")
// #define MAX_PACKET_SIZE TCP_MAXWIN // 65535 for 64-bit systems

void usage(void);
void startSniff(char*,int);
pcap_t* initializeDevice(char*);
void processPacket(u_char *, const struct pcap_pkthdr*, const u_char *);
u_int16_t handle_ethernet(u_char *, const struct pcap_pkthdr*,const u_char*);
u_char* handle_IPv4(u_char *,const struct pcap_pkthdr* ,const u_char*);
u_char* handle_IPv6(u_char *,const struct pcap_pkthdr* ,const u_char*);
inline void* my_malloc(size_t size);
void addToFlowList(char*, char*, int, int, int, int, int);
void initializeStatStruct();
struct my_flow* initializeFlowNode(char *, char *, int, int, int, int);
void printTCP(int,int,int,int,int);
void printUDP(int,int,int,int);
void printFlows();

struct my_ip {
	u_int8_t	ip_vhl;		/* header length, version */
#define IP_V(ip)	(((ip)->ip_vhl & 0xf0) >> 4)
#define IP_HL(ip)	((ip)->ip_vhl & 0x0f)
	u_int8_t	ip_tos;		/* type of service */
	u_int16_t	ip_len;		/* total length */
	u_int16_t	ip_id;		/* identification */
	u_int16_t	ip_off;		/* fragment offset field */
#define	IP_DF 0x4000		/* dont fragment flag */
#define	IP_MF 0x2000		/* more fragments flag */
#define	IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
	u_int8_t	ip_ttl;		/* time to live */
	u_int8_t	ip_p;		/* protocol */
	u_int16_t	ip_sum;		/* checksum */
	struct	in_addr ip_src,ip_dst;	/* source and dest address */
};

struct my_flow {
	char *srcIP;
	char *dstIP;
	int srcPORT;
	int dstPORT;
	int ip_version;
	int isTCP;
	int retrPackets;
	int prevSequenceNo;
	struct my_flow *next;
};

struct globalStats{
	size_t totalPackets;
	size_t totalTcpBytes;
	size_t totalUdpBytes;
	size_t totalTcpPackets;
	size_t totalUdpPackets;
};