#include "ping.h"

/**
 * A ping program that is a clone to the ping program on MacOs 
 */
int main(int argc, char *argv[])
{
    // display help menu
    if (argc != 2)
    {
        printf("usage:\n");
        return 0;
    }
    // host name or ip address
    const char *host = argv[1];
    int port = 0;

    int pid = getpid(); // process id
    struct protoent *protocol = getprotobyname("ICMP");
    struct hostent *hostname = gethostbyname(host);
    struct hostent hostname_cp;
    if (!hostname)
    {
        printf("cannot resolve hostname\n");
    }
    struct sockaddr_in ping_address;
    memset(&ping_address, 0, sizeof(struct sockaddr_in)); // init ping_address
    struct sockaddr_in reply_address;
    int sk;
    int server_fd;

    memcpy(&hostname_cp, hostname, sizeof(hostname_cp));
    memcpy(&server_fd, hostname_cp.h_addr_list[0], sizeof(server_fd));
    ping_address.sin_family = hostname->h_addrtype;
    // ping_address.sin_family = AF_INET;
    ping_address.sin_addr.s_addr = *(long *)hostname->h_addr;
    // ping_address.sin_addr.s_addr = server_fd;
    // memcpy(&ping_address.sin_addr, hostname->h_addr, sizeof(ping_address.sin_addr));
    ping_address.sin_port = htons(port);
    // ping_address.sin_port = port;

    // send a ping

    // setup socket
    sk = socket(AF_INET, SOCK_RAW, protocol->p_proto);
    if (sk < 0)
    {
        printf("ping: socket error\n");
        return 1;
    }

    const int val = 255;
    // setsockopt(sk, SOL_SOCKET, IP_TTL, &val, sizeof(val));
    // fcntl(sk, F_SETFL, O_NONBLOCK);

    struct icmp ping_packet;
    char packet[192];

    struct icmp recv_packet;

    int ret;
    int num;

    // initialize packet
    // ping_packet = (struct icmp *)packet;
    memset(&ping_packet, 0, sizeof(ping_packet));
    ping_packet.icmp_type = ICMP_ECHO;
    ping_packet.icmp_cksum = checksum(&ping_packet, sizeof(ping_packet));

    struct timeval time_sent, time_received;
    struct timeval timeout;
    fd_set mask;
    fd_set read_mask;

    FD_ZERO(&mask);
    FD_SET(sk, &mask);

    ret = sendto(sk, &ping_packet, sizeof(ping_packet), 0,
                 (struct sockaddr *)&ping_address, sizeof(ping_address));
    printf("send status ret %d\n", ret);

    ret = sendto(sk, &ping_packet, sizeof(ping_packet), 0,
                 (struct sockaddr *)&ping_address, sizeof(ping_address));
    printf("send status ret %d\n", ret);
    for (;;)
    {
        read_mask = mask;
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        num = select(FD_SETSIZE, &read_mask, NULL, NULL, &timeout);
        if (num > 0)
        {
            if (FD_ISSET(sk, &read_mask))
            {
                int len;
                ret = recvfrom(sk, &recv_packet, sizeof(recv_packet), 0,
                               (struct sockaddr *)&reply_address, &len);
                // int server_ip = client_addr.sin_addr.s_addr;

                // record current time and report
                // struct timeval current_time;
                // gettimeofday(&current_time, NULL);
                // struct timeval diff_time = diffTime(current_time, start_time);
                // double msec = diff_time.tv_sec * 1000 + ((double)diff_time.tv_usec) / 1000;
                // sprintf(out, "Report: RTT of a UDP packet is %f ms with sequence number %d\n", msec, echo_packet.seq);
                printf("received an icmp packet with ret %d\n", ret);
                if (recv_packet.icmp_type == ICMP_ECHOREPLY)
                {
                    printf("reply packet!\n");
                }
                // return 0; // terminate after report
            }
        }
        else
        {
            // printf("Haven't heard response for over %d seconds, timeout!\n", 1);
            ret = sendto(sk, &ping_packet, sizeof(ping_packet), 0,
                         (struct sockaddr *)&ping_address, sizeof(ping_address));
            printf("send status ret %d\n", ret);

            // ret = sendto(sk, &ping_packet, sizeof(ping_packet), 0,
            //              (struct sockaddr *)&ping_address, sizeof(ping_address));
            // printf("send status ret %d\n", ret);

            // return 0;
        }
    }

    return 0;
}

// int checksum(unsigned short *buffer, int len)
// {
//     int csum = 0;
//     int count_to = (len / 2) * 2;
//     int count = 0;
//     while (count < count_to)
//     {
//         int cur_val = buffer[count + 1] * 256 + buffer[count];
//         csum = csum + cur_val;
//         csum = csum & 0xffffffff;
//         count += 2;
//     }

//     if (count_to < len)
//     {
//         csum = csum + buffer[len - 1];
//         csum = csum & 0xffffffff;
//     }

//     csum = (csum >> 16) + (csum & 0xffff);
//     csum = csum + (csum >> 16);
//     int result = ~csum;
//     result = result & 0xffff;
//     result = result >> 8 | (result << 8 & 0xff00);
//     return result;
// }
unsigned short checksum(void *b, int len)
{
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}
