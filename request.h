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

void init_request(request_struct *request);
ssize_t init_whohas_request(request_struct *request);
inline void get_add2sending_list(request_item_struct *request_item,
                                 packet2send_sturct *sending_list);
#endif
