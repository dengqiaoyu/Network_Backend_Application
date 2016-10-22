#ifndef RESPONSE_H
#define RESPONSE_H
#include <stdio.h>
#include <stdlib.h>
#include "constant.h"
#include "packet.h"
#include "request.h"

typedef struct response_item_struct
{
    char peer_addr[16];
    unsigned short peer_port;
    char unused[14];
    packet_sturct *packet_ptr;
    struct response_item_struct *next;
} response_item_struct;

typedef struct response_struct
{
    response_item_struct *whohas_ptr;
} response_struct;


inline char get_packet_type(packet_sturct *packet);
inline unsigned short get_packet_len(packet_sturct *packet);
ssize_t init_responses(response_struct *response_list, char *buf,
                       unsigned short buflen,
                       char *peer_addr, unsigned short peer_port);
inline response_item_struct *find_last_rep_ptr(response_item_struct *item_ptr);
#endif