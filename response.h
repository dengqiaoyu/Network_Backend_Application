#ifndef RESPONSE_H
#define RESPONSE_H
#include <stdio.h>
#include <stdlib.h>
#include "constant.h"
#include "packet.h"
#include "request.h"
#include "hashtable.h"

typedef packet2send_sturct response_item_struct;

typedef struct response_struct
{
    response_item_struct *whohas_ptr;
} response_struct;

response_struct *init_response_list();
inline char get_packet_type(packet_sturct *packet);
inline unsigned short get_packet_len(packet_sturct *packet);
ssize_t init_responses(response_struct *response_list, char *buf,
                       unsigned short buflen,
                       char *peer_addr, unsigned short peer_port);
ssize_t process_request(response_struct *response_list,
                        packet2send_sturct *sending_list,
                        hashtable_t *haschunk_hash_table);
packet2send_sturct *get_ihave_response(response_item_struct *response_item,
                                       hashtable_t *haschunk_hash_table);
void packet_add2sending_list(packet2send_sturct *packet2send,
                             packet2send_sturct *sending_list);
inline response_item_struct *find_last_rep_ptr(response_item_struct *item_ptr);
#endif