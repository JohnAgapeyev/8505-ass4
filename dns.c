#include <arpa/inet.h>
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

#define INTERFACE_NAME "wlp2s0"

//#define GATEWAY_IP "192.168.0.1"
//#define TARGET_IP "192.168.0.2"
#define GATEWAY_IP "1.1.1.1"
#define TARGET_IP "8.8.8.8"

char local_mac[6];

char gateway_mac[6];
char target_mac[6];

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

char *get_mac_from_ip(int sock, const char *ip) {
    int size;

    uint32_t ip_int = convert_ip_to_int(ip);

    unsigned char buffer[65535];

    struct iphdr *iph;

    char *output_mac = malloc(6);

    while ((size = read(sock, buffer, 65535)) > 0) {
        printf("Read packet\n");
        //Check packet type
        if (size < 40) {
            //Size is too low
            printf("Too small\n");
            continue;
        }
        iph = (struct iphdr *) (buffer + 14);
        if (iph->daddr == ip_int) {
            printf("Good ip\n");
            //Correct IP address
            memcpy(output_mac, buffer, 6);
            return output_mac;
        }
        printf("Bad ip\n");
    }
    free(output_mac);
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

    int pack_sock = socket(AF_PACKET, SOCK_RAW, 0);

    get_local_mac(pack_sock);

    ping_ip(GATEWAY_IP);
    ping_ip(TARGET_IP);

    printf("%08x\n", gateway_ip);
    printf("%08x\n", target_ip);

    if (!fork()) {
        sleep(2);
        ping_ip(GATEWAY_IP);
    } else {
        printf("%p\n", get_mac_from_ip(pack_sock, GATEWAY_IP));
    }


    return EXIT_SUCCESS;
}
