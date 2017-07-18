#ifndef _PACKET_H
#define _PACKET_H

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "constant.h"


typedef enum {WHOHAS, IHAVE, GET, DATA, ACK, DENIED} packet_type_code_enum;

typedef struct packet_sturct
{
    char magic_number[2];
    char version_number[1];
    char packet_type[1];
    char header_length[2];
    char total_packet_length[2];
    char sequence_number[4];
    char acknowldgment_number[4];
    char pay_load[PACKET_MAXSIZE - 16];
} packet_sturct;

typedef struct packet2send_sturct
{
    char peer_addr[16];
    unsigned short peer_port;
    char unused[14];
    packet_sturct *packet_ptr;
    struct packet2send_sturct *next;
} packet2send_sturct;

inline packet_sturct *init_packet();
inline void set_ip_port(packet2send_sturct *packet2send, char *peer_addr,
                        unsigned short peer_port);
void packet2net(packet_sturct *packet);
void packet2host(packet_sturct *packet);

#endif