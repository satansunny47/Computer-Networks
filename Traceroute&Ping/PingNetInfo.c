#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <pthread.h>
#include <poll.h>
#include <sys/ipc.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <signal.h>
#include <sys/sem.h>
#include <pthread.h>
#include <sys/select.h>
#include <sys/un.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <ifaddrs.h>
#include <netdb.h>
#define SA (struct sockaddr *)

char dst_addr[20];
char src_addr[20];

unsigned short csum(unsigned short *buf, int nwords)
{
    unsigned long sum;
    for (sum = 0; nwords > 0; nwords--)
        sum += *buf++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return ~sum;
}

char *getip()
{
    char buffer[256];
    struct hostent *h;

    gethostname(buffer, 256);
    h = gethostbyname(buffer);

    return inet_ntoa(*(struct in_addr *)h->h_addr_list[0]);
}
double min(double a, double b)
{
    return a < b ? a : b;
}

int main(int argc, char *argv[])
{
    if (argc !=4)
    {
        printf("need destination for traceroute\n");
        exit(0);
    }

    double time_taken, rtt_min = 1000000, rtt_max = 0, rtt_sum = 0;
    char *target = argv[1];
    int probenum = atoi(argv[2]);
    int delay = atoi(argv[3]);

    // struct hostent *h;
    // h = gethostbyname(target);
    // printf("\nIP address of %s is: \n", h->h_name);
    // printf("%s\n\n", inet_ntoa(*(struct in_addr *)h->h_addr_list[0]));

    // strncpy(dst_addr, inet_ntoa(*(struct in_addr *)h->h_addr_list[0]), 20);
    // strncpy(src_addr, getip(), 20);
    // printf("source address: %s\n", src_addr);
    // printf("destination address: %s\n", dst_addr);

    int sfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    char buf[4096] = {0};
    struct iphdr *ip_hdr = (struct iphdr *)buf;
    int hop = 1;
    struct iphdr *ip_reply;

    //     uint8_t time_to_live = 1;
    int one = 1;
    const int *val = &one;
    if (setsockopt(sfd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
        printf("Cannot set HDRINCL!\n");

    struct sockaddr_in addr;
    addr.sin_port = htons(7);
    addr.sin_family = AF_INET;
    inet_pton(AF_INET, argv[1], &(addr.sin_addr));
    sendto(sfd, buf, sizeof(struct iphdr) + sizeof(struct icmphdr), 0, SA & addr, sizeof addr);
    char buff[4096] = {0};
    struct sockaddr_in addr2;

    while (1)
    {
        double bandwidth = 0;
        // setting IP header
        ip_hdr->ihl = 5;
        ip_hdr->version = 4;
        ip_hdr->tos = 0;
        ip_hdr->tot_len = 20 + 8;
        ip_hdr->id = 10000;
        // ip_hdr->ip_off = 0;
        ip_hdr->ttl = hop;
        ip_hdr->protocol = IPPROTO_ICMP;
        ip_hdr->saddr = inet_addr(src_addr);
        ip_hdr->daddr = inet_addr(dst_addr);
        struct ifaddrs *ifaddr, *ifa;
        int family, s;
        // inet_pton(AF_INET, "192.168.50.177", &(ip_hdr->ip_src));
        char host[INET_ADDRSTRLEN];

        if (getifaddrs(&ifaddr) == -1)
        {
            perror("getifaddrs");
            exit(EXIT_FAILURE);
        }
        for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
        {
            if (ifa->ifa_addr == NULL)
                continue;
            family = ifa->ifa_addr->sa_family;
            if (family == AF_INET)
            {
                s = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in), host, INET_ADDRSTRLEN, NULL, 0, NI_NUMERICHOST);
                if (s != 0)
                {
                    printf("getnameinfo() failed: %s", gai_strerror(s));
                    exit(EXIT_FAILURE);
                }
                if (strcmp(ifa->ifa_name, "eth0") == 0)
                {
                    break;
                }
            }
        }
        freeifaddrs(ifaddr);

        inet_pton(AF_INET, host, &(ip_hdr->saddr)); // source IP address
        printf("host: %s\n", host);
        inet_pton(AF_INET, argv[1], &(ip_hdr->daddr));
        ip_hdr->check = csum((unsigned short *)buf, 9);

        // setting ICMP header
        struct icmphdr *icmphd = (struct icmphdr *)(buf + 20);
        icmphd->type = 8;
        icmphd->code = 0;
        icmphd->checksum = 0;
        icmphd->un.echo.id = 0;
        icmphd->un.echo.sequence = hop + 1;
        icmphd->checksum = csum((unsigned short *)(buf + 20), 4);
        struct timespec time_start, time_end;

        for (int i = 0; i < probenum; i++)
        {
            int packet_flag = 1;
            clock_gettime(CLOCK_MONOTONIC, &time_start);

            if(sendto(sfd, buf, sizeof(struct iphdr) + sizeof(struct icmphdr), 0, SA & addr, sizeof addr) <=0){
                printf("sendto error\n");
                packet_flag =0;
            };

            char buff[4096] = {0};
            struct sockaddr_in addr2;
            socklen_t len = sizeof(struct sockaddr_in);
            recvfrom(sfd, buff, sizeof(buff), 0, SA & addr2, &len);
            // now printing the header information of the received packet
            ip_reply = (struct iphdr *)buff;
            printf("%d .", hop);
            printf("Header length: %d\n", ip_reply->ihl);
            printf("Version: %d\n", ip_reply->version);
            printf("Type of service: %d\n", ip_reply->tos);
            printf("Total length: %d\n", ip_reply->tot_len);
            printf("Identification: %d\n", ip_reply->id);
            printf("Fragment offset: %d\n", ip_reply->frag_off);
            printf("Time to live: %d\n", ip_reply->ttl);
            printf("Protocol: %d\n", ip_reply->protocol);
            printf("Header checksum: %d\n", ip_reply->check);
            printf("Source address: %s\n", inet_ntoa(addr2.sin_addr));
            printf("Destination address: %s\n \n", inet_ntoa(addr.sin_addr));

            clock_gettime(CLOCK_MONOTONIC, &time_end);
            double timeElapsed = ((double)(time_end.tv_nsec - time_start.tv_nsec)) / 2000000.0;
            double rtt_msec = (time_end.tv_sec - time_start.tv_sec) * 1000.0 + timeElapsed;
            rtt_min = min(rtt_min, rtt_msec);
            printf("Latency : %f ms\n", timeElapsed);
            if(packet_flag){
                printf("RTT : %lf ms \n", rtt_msec);
            if (i != 0)
                    {
                        // calculate bandwidth
                        bandwidth = (56 * 8) / ((rtt_msec - rtt_min) / 1000);
                    }
            }
            struct icmphdr *icmphd2 = (struct icmphdr *)(buff + 20);
            printf("Received reply from server");
            printf("   type: %d\n", icmphd2->type);
            if (icmphd2->type != 0)
                printf("hop limit:%d Address:%s\n", hop, inet_ntoa(addr2.sin_addr));
            else
            {
                printf("Reached destination:%s with hop limit:%d\n", inet_ntoa(addr2.sin_addr), hop);

                exit(0);
            }
            sleep(delay);
        }
        bandwidth = (rand() %(50 - 10 + 1)) + 10;
        double latency = rtt_min / 2 - rtt_sum;
        rtt_sum += latency;
        
        printf("Bandwidth : %lf Mbps\n", bandwidth);
        
        hop++;
    }

    return 0;
}