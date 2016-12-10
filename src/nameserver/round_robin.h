#ifndef ROUND_ROBIN_H
#define ROUND_ROBIN_H
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "dijkstra.h"

typedef struct server_loop_queue_s
{
    char server_array[MAX_S_NUM][MAX_LINE];
    size_t len;
    size_t next_position;
} server_loop_queue_t;

void round_robin(server_loop_queue_t *server_loop_queue, char *server_ip);
void init_server_loop_queue(char s_ip_array[MAX_S_NUM][MAX_LINE], size_t s_num,
                            server_loop_queue_t *server_loop_queue);
#endif