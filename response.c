#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "constant.h"
#include "packet.h"
#include "request.h"
#include "response.h"
#include "debug.h"


inline char get_packet_type(packet_sturct *packet)
{
    return *packet->packet_type;
}

inline unsigned short get_packet_len(packet_sturct *packet)
{
    return *(unsigned short *)packet->total_packet_length;
}

ssize_t init_responses(response_struct *response_list, char *buf,
                       unsigned short buflen,
                       char *peer_addr, unsigned short peer_port)
{
    unsigned short bufoffset = 0;
    response_item_struct *last_whohas =
        find_last_rep_ptr(response_list->whohas_ptr);
    while (bufoffset < buflen)
    {
        char packet_type = get_packet_type((packet_sturct *)(buf + bufoffset));
        unsigned short packet_len =
            get_packet_len((packet_sturct *)(buf + bufoffset));
        if (packet_len > buflen - bufoffset)
        {
            return -1;
        }
        bufoffset += packet_len;
        switch ((int)packet_type)
        {
        case 0: // WHOHAS
            last_whohas->next = malloc(sizeof(response_item_struct));
            last_whohas = last_whohas->next;
            memset(last_whohas, 0, sizeof(response_item_struct));
            strncpy(last_whohas->peer_addr, peer_addr, 16);
            last_whohas->peer_port = peer_port;
            last_whohas->packet_ptr = malloc(packet_len);
            memset(last_whohas->packet_ptr, 0, packet_len);
            memcpy(last_whohas->packet_ptr, buf + bufoffset, packet_len);
            break;
        case 1:
            break;
        case 2:
            break;
        case 3:
            break;
        case 4:
            break;
        case 5:
            break;
        default:
            break;
        }
    }
}

inline response_item_struct *find_last_rep_ptr(response_item_struct *item_ptr)
{
    response_item_struct *rover = item_ptr;
    while (rover->next != NULL)
    {
        rover = rover->next;
    }
    return rover;
}