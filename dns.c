#include <arpa/inet.h>
#include <errno.h>
#include <linux/if.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <net/ethernet.h>
#include <netdb.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/raw.h>
#include <sys/socket.h>
#include <unistd.h>

#define INTERFACE_NAME "enp0s31f6"

//#define GATEWAY_IP "192.168.0.1"
//#define TARGET_IP "192.168.0.2"
#define GATEWAY_IP "1.1.1.1"
#define TARGET_IP "8.8.8.8"

unsigned char local_mac[6];

unsigned char gateway_mac[6];
unsigned char target_mac[6];

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

    unsigned char m[30];
    if (get_mac_from_ip(pack_sock, GATEWAY_IP, m)) {
        perror("Initial gateway mac read");
        exit(EXIT_FAILURE);
    }
    printf("%02x %02x %02x %02x %02x %02x\n", m[0], m[1], m[2], m[3], m[4], m[5]);

    return EXIT_SUCCESS;
}
