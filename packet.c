#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "constant.h"
#include "packet.h"

inline packet_sturct *init_packet()
{
    packet_sturct *packet = malloc(sizeof(packet_sturct));
    memset(packet, 0, sizeof(packet_sturct));
    *((unsigned short *)packet->magic_number) =
        (unsigned short)15441;
    *(packet->version_number) = 1;
    *(packet->packet_type) = 255;
    *((unsigned short *)packet->header_length) =
        (unsigned short)16;
    *((unsigned short *)packet->total_packet_length) =
        (unsigned short)16;
    *((unsigned int *)packet->sequence_number) =
        (unsigned int)(4294967295);
    *((unsigned int *)packet->acknowldgment_number) =
        (unsigned int)(4294967295);

    return packet;
}

inline void set_ip_port(packet2send_sturct *packet2send, char *peer_addr,
                        unsigned short peer_port)
{
    strncpy(packet2send->peer_addr, peer_addr, 16);
    packet2send->peer_port = peer_port;
}