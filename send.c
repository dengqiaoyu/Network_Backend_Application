#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include "constant.h"
#include "packet.h"
#include "request.h"
#include "response.h"
#include "send.h"
#include "debug.h"

packet2send_sturct *init_sending_list()
{
    packet2send_sturct *sending_list = malloc(sizeof(packet2send_sturct));
    memset(sending_list, 0, sizeof(packet2send_sturct));
    return sending_list;
}

ssize_t send_udp(int sock, packet2send_sturct *sending_list)
{
    ssize_t writeret = 0;
    packet2send_sturct *rover_last = sending_list;
    packet2send_sturct *rover = sending_list->next;
    while (rover != NULL)
    {
        dbg_cp1_printf("sending packets...\n");
        struct sockaddr_in addr;
        bzero(&addr, sizeof(addr));
        inet_pton(AF_INET, rover->peer_addr, &addr);
        addr.sin_family = AF_INET;
        addr.sin_port = htons(rover->peer_port);
        unsigned short packet_len =
            *((unsigned short *)rover->packet_ptr->total_packet_length);
        writeret = sendto(sock, rover->packet_ptr, packet_len, 0,
                          (struct sockaddr *)&addr, sizeof(addr));
        if (writeret == -1)
        {
            int errsv = errno;
            if (errsv == EAGAIN || errno == EWOULDBLOCK)
            {
                break;
            }
            else
            {
                printf("error: %s\n", strerror(errsv));
                return -1;
            }
        }
        else
        {
            if (writeret != packet_len)
            {
                break;
            }
            else
            {
                rover_last->next = rover->next;
                free(rover->packet_ptr);
                free(rover);
                rover = rover_last->next;
            }
        }
    }
    if (sending_list->next != NULL)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

inline packet2send_sturct *find_last_send_ptr(packet2send_sturct *packet2send)
{
    packet2send_sturct *rover = packet2send;
    while (rover->next != NULL)
    {
        rover = rover->next;
    }
    return rover;
}