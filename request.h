#ifndef REQUEST_H
#define REQUEST_H
#include <stdio.h>
#include <stdlib.h>
#include "constant.h"
#include "packet.h"

typedef struct request_item_struct
{
    char peer_addr[16];
    unsigned short peer_port;
    char unused[14];
    packet_sturct *packet_ptr;
    struct request_item_struct *next;
} request_item_struct;

typedef request_item_struct request_to_send_struct;

typedef struct request_struct
{
    char get_chunk_file[PATH_MAXSIZE];
    char out_put_file[PATH_MAXSIZE];
    request_item_struct *whohas_ptr;
    request_item_struct *get_ptr;
} request_struct;
#endif

void init_request(request_struct *request);
ssize_t init_whohas_request(request_struct *request);
inline void add2sending_list(request_item_struct *request_item,
                             request_to_send_struct *sending_list);
ssize_t send_request(int sock, request_to_send_struct *sending_list);