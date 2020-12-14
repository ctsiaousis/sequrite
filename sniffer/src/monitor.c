#include "monitor.h"
#include <stdint.h>

/*
 *      For extended pcap library functions:
 *  https://docs.oracle.com/cd/E88353_01/html/E37845/pcap-3pcap.html
 *
 */

pcap_t *handle;
static uint16_t previousSequenceNumber = 0;
struct my_flow *head_flowList = NULL;
struct globalStats* gStat = NULL;
static volatile int breakLoop = 0;
void intHandler(int dummy) {
    printf("\nGot your request master.\n"); 
    breakLoop = 1;
}

void processPacket(u_char *arg, const struct pcap_pkthdr* header, const u_char * packet){
    if( breakLoop ){
        pcap_breakloop(handle);
    }else{
        clear();
        u_int16_t type = handle_ethernet(arg,header,packet);
        if(type == ETHERTYPE_IP){
            printf("----------------------------------------------------\n");
            handle_IPv4(arg, header, packet);
            printf("----------------------------------------------------\n");
        }else if(type == ETHERTYPE_IPV6){
            printf("----------------------------------------------------\n");
            handle_IPv6(arg, header, packet);
            printf("----------------------------------------------------\n");

        }
        // int *counter = (int *)arg;
        // printf("Processed Packets: %d\n", ++(*counter)); 
        // printf("Received Packet Size: %d\n", header->len); 
        gStat->totalPackets++;
        printf("\nPress Ctrl-C to stop sniffing.");
        fflush(stdout);
    }
    return;
}

////////////////////////////////////////////////////////////////////////////////////
///                          Header Handling Functions                           ///
////////////////////////////////////////////////////////////////////////////////////
u_int16_t handle_ethernet(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char *packet){
    struct ether_header *eptr = (struct ether_header *) packet;
    return ntohs(eptr->ether_type);
}

u_char* handle_IPv4(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char*packet){
    
    const struct my_ip* ip;
    u_int ip_hlen,off,version;
    char* srcIP = NULL;
    char* dstIP = NULL;
    int dstPort, srcPort;
    int protocolDATAlen;
    int len;

    /* jump pass the ethernet header */
    ip = (struct my_ip*)(packet + sizeof(struct ether_header));
    u_int protocHDRlength = pkthdr->len;
    protocHDRlength -= sizeof(struct ether_header); 
    len     = ntohs(ip->ip_len);
    ip_hlen = IP_HL(ip); // IP header length
    version = IP_V(ip); // IP version
    /* check version */
    if(version != 4 && version != 6){
      fprintf(stdout,"Unknown version %d\n",version);
      return NULL;
    }
    /* check header length */
    if(ip_hlen < 5 ){
        fprintf(stdout,"bad IPheader len %d \n",ip_hlen);
        return NULL;
    }
    /* see if we have as much packet as we should */
    if(protocHDRlength < len)
        printf("\ntruncated IP - %d bytes missing\n",len - protocHDRlength);

    /* Check to see if we have the first fragment */
    // off = ntohs(ip->ip_off);
    // if((off & 0x1fff) == 0 ){// no 1's in first 13 bits
    srcIP = inet_ntoa(ip->ip_src);
    printf("IPsrc: \t\t%s\n", srcIP);
    dstIP = inet_ntoa(ip->ip_dst);
    printf("IPdst: \t\t%s\n", dstIP);
    printf("version: \tIPv%d\n", version);

    if(ip->ip_p == IPPROTO_TCP){
        const struct tcphdr* tcp_header;
        tcp_header = (struct tcphdr*)(packet + ETHER_HDR_LEN + sizeof(struct my_ip));
        srcPort = ntohs(tcp_header->source);
        dstPort = ntohs(tcp_header->dest);
        protocHDRlength = protocHDRlength - sizeof(struct my_ip);
        protocolDATAlen = protocHDRlength - sizeof(struct tcphdr);
        uint16_t seqNo = ntohs(tcp_header->seq);
        printTCP(srcPort,dstPort,protocHDRlength,protocolDATAlen,seqNo);
        addToFlowList(srcIP,dstIP,srcPort,dstPort,6,1,seqNo);
        gStat->totalTcpPackets++; // <- global variable
        gStat->totalTcpBytes+= protocHDRlength; // <- global variable
    }else if(ip->ip_p == IPPROTO_UDP){
        const struct udphdr* udp_header;
        udp_header = (struct udphdr*)(packet + ETHER_HDR_LEN + sizeof(struct my_ip));
        srcPort = ntohs(udp_header->source);
        dstPort = ntohs(udp_header->dest);
        protocHDRlength = protocHDRlength - sizeof(struct my_ip);
        protocolDATAlen = protocHDRlength - sizeof(struct udphdr);
        printUDP(srcPort, dstPort, protocHDRlength, protocolDATAlen);
        addToFlowList(srcIP,dstIP,srcPort,dstPort,version, 0, 0);
        gStat->totalUdpPackets++; // <- global variable
        gStat->totalUdpBytes+= protocHDRlength; // <- global variable
    }else{
        fprintf(stdout,"IPv4::Unknown %d\n", ip->ip_p);
    }
    // }

    return NULL;
}


/* Handle IPv6 header */
u_char* handle_IPv6(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char*packet){
    char srcIP[INET6_ADDRSTRLEN], dstIP[INET6_ADDRSTRLEN];
    struct ip6_hdr* ip6Header;
    int srcPort = 0, dstPort = 0;
    u_int protocolDATAlen = 0;
    u_int protocHDRlength = pkthdr->len;
    protocHDRlength -= sizeof(struct ether_header); 
    ip6Header = (struct ip6_hdr*)(packet + sizeof(struct ether_header));
    inet_ntop(AF_INET6, &(ip6Header->ip6_src), srcIP, INET6_ADDRSTRLEN);
	inet_ntop(AF_INET6, &(ip6Header->ip6_dst), dstIP, INET6_ADDRSTRLEN);
	
	int nextheader = ip6Header->ip6_nxt;

    printf("IPsrc: \t\t%s\n", srcIP);
    printf("IPdst: \t\t%s\n", dstIP);
    printf("version: \tIPv6\n");
    if(nextheader == IPPROTO_TCP){
        struct tcphdr* tcp_header;
        tcp_header = (struct tcphdr*)(packet + ETHER_HDR_LEN + sizeof(struct ip6_hdr));
        srcPort = ntohs(tcp_header->source);
        dstPort = ntohs(tcp_header->dest);
        protocHDRlength = protocHDRlength - sizeof(struct ip6_hdr);
        protocolDATAlen = protocHDRlength - sizeof(struct tcphdr);
        uint16_t seqNo = ntohs(tcp_header->seq);
        printTCP(srcPort,dstPort,protocHDRlength,protocolDATAlen,seqNo);
        addToFlowList(srcIP,dstIP,srcPort,dstPort,6,1,seqNo);
        gStat->totalTcpPackets++; // <- global variable
        gStat->totalTcpBytes+=protocHDRlength; // <- global variable
    }else if(nextheader == IPPROTO_UDP){
		const struct udphdr* udp_header;
        udp_header = (struct udphdr*)(packet + ETHER_HDR_LEN + sizeof(struct ip6_hdr));
        srcPort = ntohs(udp_header->source);
        dstPort = ntohs(udp_header->dest);
        protocHDRlength = protocHDRlength - sizeof(struct ip6_hdr);
        protocolDATAlen = protocHDRlength - sizeof(struct udphdr);
        printUDP(srcPort, dstPort, protocHDRlength, protocolDATAlen);
        addToFlowList(srcIP,dstIP,srcPort,dstPort,6, 0, 0);

        gStat->totalUdpPackets++; // <- global variable
        gStat->totalUdpBytes+=protocHDRlength; // <- global variable
	}else{
		printf("IPv6::Unknown %d\n", nextheader);
    }
    return NULL;
}


////////////////////////////////////////////////////////////////////////////////////
///                            Flow Handling Functions                           ///
////////////////////////////////////////////////////////////////////////////////////
struct my_flow* initializeFlowNode(char *srcAddress, char *dstAddress, int srcPort, int dstPort, int version, int isTCP){
    struct my_flow* newNode = (struct my_flow*)my_malloc(sizeof(struct my_flow));
    newNode->srcIP = (char*)my_malloc( INET_ADDRSTRLEN);
    memcpy(newNode->srcIP, srcAddress, INET_ADDRSTRLEN);
    newNode->dstIP = (char*)my_malloc( INET_ADDRSTRLEN);
    memcpy(newNode->dstIP, dstAddress, INET_ADDRSTRLEN);
    newNode->srcPORT = srcPort;
    newNode->dstPORT = dstPort;
    newNode->ip_version = version;
    newNode->isTCP = isTCP;
    newNode->retrPackets = 0;
    newNode->prevSequenceNo = 0;
    newNode->next = NULL;
    return newNode;
}

void addToFlowList(char *srcAddress, char *dstAddress, int srcPort, int dstPort, int version, int isTCP, int seqNo){
    struct my_flow* newNode = initializeFlowNode(srcAddress, dstAddress, srcPort, dstPort, version, isTCP);
    if(head_flowList == NULL){
        //list is empty, make it header
        head_flowList = newNode;
        return;
    }else{
        struct my_flow* tmp = head_flowList;
        while(tmp != NULL){
            int conditionA = (strcmp(tmp->srcIP, newNode->srcIP) == 0);
            int conditionB = (strcmp(tmp->dstIP, newNode->dstIP) == 0);
            int conditionC = (tmp->srcPORT == newNode->srcPORT);
            int conditionD = (tmp->dstPORT == newNode->dstPORT);
            int conditionE = (tmp->ip_version == newNode->ip_version);
            if( conditionA && conditionB && conditionC && conditionD && conditionE){
                if(isTCP){
                    if(tmp->prevSequenceNo <= seqNo){
                        tmp->prevSequenceNo = seqNo;
                    }else{
                        tmp->retrPackets++;
                    }
                }
                break; // network flow already exists in list
            }else if(tmp->next == NULL){
                //not found and we are at the end
                tmp->next = newNode;
            }else{
                tmp = tmp->next;
            }
        }
    }
}

////////////////////////////////////////////////////////////////////////////////////
///                           Printing Info Functions                            ///
////////////////////////////////////////////////////////////////////////////////////

void printUDP(int srcPort, int dstPort, int HDRlength, int DATAlength){
    printf("SRC Port: \t%d\n",srcPort);
    printf("DST Port: \t%d\n",dstPort);
    printf("-------------------+\n");
    printf("Packet Type: \tUDP|\n");
    printf("---+---------------+\n");
    printf("UDP| header length: \t%d\n",HDRlength);
    printf("UDP| data length: \t%d\n",DATAlength);
}
void printTCP(int srcPort,int dstPort,int HDRlength,int DATAlen,int seqNo){
    printf("SRC Port: \t%d\n",srcPort);
    printf("DST Port: \t%d\n",dstPort);
    printf("-------------------+\n");
    printf("Packet Type: \tTCP|\n");
    printf("---+---------------+\n");
    printf("TCP| header length: \t%d\n",HDRlength);
    printf("TCP| data length: \t%d\n",DATAlen);
    printf("TCP| SEQ number: \t%d\n",seqNo);
}

void printFlows(){
    struct my_flow* tmp = head_flowList;
    size_t counter = 0;
    while(tmp != NULL){
        printf("Flow_%zu: [ srcIP: %s    \t", ++counter, tmp->srcIP);
        printf("dstIP: %s  \tsrcPORT: %d\t",tmp->dstIP, tmp->srcPORT);
        printf("dstPORT: %d\tIPv%d",tmp->dstPORT,tmp->ip_version);
        if(tmp->isTCP){
            printf("\tTCP\t");
            printf("re-Transmissions: %d ]\n",tmp->retrPackets);
        }else{
            printf("\tUDP ]\n");
        }
        tmp = tmp->next;
    }
}

////////////////////////////////////////////////////////////////////////////////////
///                          Initialization Functions                            ///
////////////////////////////////////////////////////////////////////////////////////

void startSniff(char* name,int isFile){
    const u_char* packet;
    char errbuf[PCAP_ERRBUF_SIZE];

    initializeStatStruct();

    if(isFile){
        if((handle = pcap_open_offline(name, errbuf)) == NULL){
            exit(EXIT_FAILURE);
        }
    }else{
        if((handle = initializeDevice(name)) == NULL){
            exit(EXIT_FAILURE);
        }
    }

        /* Grab a packet */
    int i=0, count=0; 
    /* Loop forever & call processPacket() for every received packet*/ 
    if ( -1 == pcap_loop(handle, breakLoop, processPacket, (u_char *)&count) ){
        fprintf(stderr, "ERROR: %s\n", pcap_geterr(handle) );
        exit(1);
    }
    
    int tcpFlows = 0, udpFlows = 0, totalFlows = 0;
    struct my_flow* tmp = head_flowList;

    size_t retrCounter = 0;
    while(tmp != NULL){
        totalFlows ++;
        if(tmp->isTCP){
            retrCounter += tmp->retrPackets;
            tcpFlows++;
        }else{
            udpFlows++;
        }
        tmp = tmp->next;
    }
    if(isFile && !breakLoop)
        printf("%c[2K \rEnd Of File\n",27);//delete current line and print
    printf("----------------------------------------------------\n");
    printf("Flow statistics:\tTCP:%d\tUDP:%d\tTOTAL:%d\n", tcpFlows,udpFlows,totalFlows);
    printf("----------------------------------------------------\n");
    printf("Total TCP packets:\t%zu\tbytes:\t%zu\n",gStat->totalTcpPackets,gStat->totalTcpBytes);
    printf("Total UDP packets:\t%zu\tbytes:\t%zu\n",gStat->totalUdpPackets,gStat->totalUdpBytes);
    printf("Total packets:\t\t%zu\t\n",gStat->totalPackets);
    printf("----------------------------------------------------\n");
    printf("Total re-Transmissions: %zu (based on TCP SEQ numbers only)\n",retrCounter);
    /*And close the session */
    pcap_close(handle);
}

void initializeStatStruct(){
    struct globalStats *s = my_malloc(sizeof(struct globalStats));
    s->totalPackets = 0;
    s->totalTcpBytes = 0;
    s->totalTcpPackets = 0;
    s->totalUdpBytes = 0;
    s->totalUdpPackets = 0;
    gStat = s;
}

pcap_t* initializeDevice(char* devName){
    char errbuf[PCAP_ERRBUF_SIZE]; /* Error String */
    struct bpf_program fp;         /* The compliled filter expression */
    bpf_u_int32 mask;              /* The netmask of our sniffing device */
    bpf_u_int32 net;               /* The IP of our sniffering device */

    /* Find the properties for the device */
    if(pcap_lookupnet(devName, &net, &mask, errbuf) == -1){
        fprintf(stderr, "Can't get netmask for device %s\n", devName); 
        net = 0;
        mask = 0;
        return NULL;
    }
    /* Open the session in promiscuous mode */
    handle = pcap_open_live(devName, BUFSIZ, 1, 100, errbuf);
    if(handle == NULL){
        fprintf(stderr, "Couldn't open device %s: %s\n", devName, errbuf); 
        return NULL;
    }

    // if(pcap_set_snaplen(handle,MAX_PACKET_SIZE) == -1){
    //     fprintf(stderr, "Couldn't set suggested packet size. Are you on 64-bit PC?\n"); 
    //     return NULL;
    // }
    return handle;
}

////////////////////////////////////////////////////////////////////////////////////
///                            User Related Functions                            ///
////////////////////////////////////////////////////////////////////////////////////

int main(int argc, char *argv[])
{
    int opt;                 /* used for command line arguments */
    char *input_file;        /* path to the input file */
    char *interface_name;    /* path to the input file */
    input_file = NULL;
    interface_name = NULL;
    signal(SIGINT, intHandler);//SIGINT handler

    if (argv[optind] == NULL) {
        printf("Mandatory argument(s) missing\n");
        usage();
        exit(EXIT_FAILURE);
    }
    while ((opt = getopt(argc, argv, "hr:i:")) != -1) {
        switch (opt) {
        case 'r':
            input_file = strdup(optarg);
            if (input_file != NULL)
                startSniff(input_file, 1);
            break;
        case 'i':
            interface_name = strdup(optarg);
            if( interface_name != NULL)
                startSniff(interface_name, 0);
            break;
        case 'h':
        default:
            usage();
        }
    }

    printf("\nshow network flows?[y/n]  ");
    char c;
    while(1){
        scanf(" %c",&c);
        if(tolower(c) == 'y'){
            printFlows();
            break;
        }else if(tolower(c) == 'n')
            break;
        else
            printf("[y/n] ");
    }
    //should also clean structs but im lazy
    return(0);
}

inline void* my_malloc(size_t size){
    void *ptr = malloc( size);
    if( !ptr){
         printf( "Allocation failed");
         exit(EXIT_FAILURE);
    }
    return ptr;
}

void usage(void) {
    printf("\n"
           "Usage:\n"
           "    ./monitor -i in_file\n"
           "    ./monitor -h\n");
    printf("\n"
           "\t\t\t[Options]\n"
           "----------------------------------------------------------------\n"
           " -i   device   Network interface name (e.g., eth0)\n"
           " -o    path    Packet capture file name (e.g., test.pcap)\n"
           " -h            This help message\n");
    exit(EXIT_FAILURE);
}