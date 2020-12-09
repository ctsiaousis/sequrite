#include <pcap/funcattrs.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <signal.h>       
#include <pcap/pcap.h>
#include <pcap/pcap-inttypes.h>
#include <pcap/ipnet.h>
#include <pcap/socket.h>
/*
 *
 *  https://docs.oracle.com/cd/E88353_01/html/E37845/pcap-3pcap.html
 *
 */
#define clear() printf("\033[H\033[J")
#define MAX_PACKET_SIZE 65535

void usage(void);       /*help message*/
void liveSniff(char*);  /*live operation*/
pcap_t* initializeDevice(char*);
void processPacket(u_char *, const struct pcap_pkthdr*, const u_char *);
inline void* p_malloc(size_t size);

static volatile int breakLoop = 0;
pcap_t *handle;

void intHandler(int dummy) {
    printf("\rGot your request master.\n"); 
    breakLoop = 1;
}

void processPacket(u_char *arg, const struct pcap_pkthdr* header, const u_char * packet){ 
        printf("1.\n"); 
    if( breakLoop ){
        printf("2.\n"); 
        pcap_breakloop(handle);
    }else{
        printf("3.\n"); 
        int i=0, *counter = (int *)arg; 
        clear();
        printf("Packet Count: %d\n", ++(*counter)); 
        printf("Received Packet Size: %d\n", header->len); 
        printf("Payload:\n"); 
        for (i=0; i<header->len; i++){ 
        
            if ( isprint(packet[i]) ) /* If it is a printable character, print it */
               printf("%c ", packet[i]); 
            else 
               printf(". "); 

            if( (i%16 == 0 && i!=0) || i==header->len-1 )
               printf("\n");
        }
        printf("Press Ctrl-C to stop sniffing.\n"); 
    }
    return;
} 


void liveSniff(char* devName){
    const u_char* packet;
    // handle = pcap_open_dead(0,MAX_PACKET_SIZE);
    if((handle = initializeDevice(devName)) == NULL){
        exit(EXIT_FAILURE);
    }

    /* Grab a packet */
    int i=0, count=0; 
    /* Loop forever & call processPacket() for every received packet*/ 
    if ( pcap_loop(handle, breakLoop, processPacket, (u_char *)&count) == -1){
        fprintf(stderr, "ERROR: %s\n", pcap_geterr(handle) );
        exit(1);
    }

    /* Print its length */
    printf("Jacked a packet with length of [%d]\n", count);
    
    /*And close the session */
    pcap_close(handle);

}


////////////////////////////////////////////////////////////////////////////////////
///                          Device Related Functions                            ///
////////////////////////////////////////////////////////////////////////////////////

pcap_t* initializeDevice(char* devName){
    char errbuf[PCAP_ERRBUF_SIZE]; /* Error String */
    struct bpf_program fp;         /* The compliled filter expression */
    char filter_exp[] = "port 80"; /* The filter expression */
    bpf_u_int32 mask;              /* The netmask of our sniffing device */
    bpf_u_int32 net;               /* The IP of our sniffering device */

    /* Find the properties for the device */
    if(pcap_lookupnet(devName, &net, &mask, errbuf) == -1){
        fprintf(stderr, "Can't get netmask for device %s\n", devName); 
        net = 0;
        mask = 0;
        return NULL;
    }
    handle = p_malloc(512);
    /* Open the session in promiscuous mode */
    handle = pcap_open_live(devName, BUFSIZ, 1, 100, errbuf);
    if(handle == NULL){
        fprintf(stderr, "Couldn't open device %s: %s\n", devName, errbuf); 
        return NULL;
    }

    /* Compile and apply the filter */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1){
        fprintf(stderr, "Counldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return NULL;
    }

    if(pcap_setfilter(handle, &fp) == -1){
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle)); 
        return NULL;
    }

    if(pcap_set_snaplen(handle,MAX_PACKET_SIZE) == -1){
        fprintf(stderr, "Couldn't set suggested packet size. Are you on 64-bit PC?\n"); 
        return NULL;
    }
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
    /* Init arguments */
    input_file = NULL;
    interface_name = NULL;


    signal(SIGINT, intHandler);
    /*
     * Get arguments
     */
    if (argv[optind] == NULL) {
        printf("Mandatory argument(s) missing\n");
        usage();
        exit(EXIT_FAILURE);
    }
    while ((opt = getopt(argc, argv, "hr:i:")) != -1) {
        switch (opt) {
        case 'r':
            input_file = strdup(optarg);
            break;
        case 'i':
            interface_name = strdup(optarg);
            if( interface_name != NULL)
                liveSniff(interface_name);
            break;
        case 'h':
        default:
            usage();
        }
    }


    return(0);
}

inline void* p_malloc(size_t size){
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