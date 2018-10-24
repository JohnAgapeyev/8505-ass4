#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_packet.h>
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

#define GATEWAY_IP 192.168.0.1
#define TARGET_IP 192.168.0.2

char local_mac[6];

char gateway_mac[6];
char target_mac[6];

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

int main(void) {
    if (setuid(0)) {
        perror("setuid");
        exit(EXIT_FAILURE);
    }
    if (setgid(0)) {
        perror("setgid");
        exit(EXIT_FAILURE);
    }

    int pack_sock = socket(AF_PACKET, SOCK_RAW, 0);

    get_local_mac(pack_sock);

    return EXIT_SUCCESS;
}
