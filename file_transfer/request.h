#ifndef _REQUEST_H
#define _REQUEST_H
#include <stdio.h>
#include <stdlib.h>
#include "constant.h"
#include "packet.h"

typedef packet2send_sturct request_item_struct;

typedef struct request_struct
{
    char get_chunk_file[PATH_MAXSIZE];
    char out_put_file[PATH_MAXSIZE];
    request_item_struct *whohas_ptr;
    request_item_struct *get_ptr;
} request_struct;

typedef struct peer_list_struct
{
    size_t peer_id;
    char peer_addr[16];
    unsigned short peer_port;
    struct peer_list_struct *next;
} peer_list_struct;

peer_list_struct *init_peer_list();
void init_request(request_struct *request);
ssize_t init_whohas_request(request_struct *request,
                            peer_list_struct *peer_list);
ssize_t add_whohas_packet(request_struct *request, char *peer_addr,
                          unsigned short peer_port, char *pay_load,
                          unsigned short pay_load_len);
inline void get_add2sending_list(request_item_struct *request_item,
                                 packet2send_sturct *sending_list);
inline request_item_struct *find_last_req_ptr(request_item_struct *item_ptr);
#endif
