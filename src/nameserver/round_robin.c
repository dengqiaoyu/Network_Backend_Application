#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "round_robin.h"

void round_robin(server_loop_queue_t *server_loop_queue, char *server_ip)
{
    size_t next_position = server_loop_queue->next_position;
    strncpy(server_ip, server_loop_queue->server_array[next_position], 15);
    next_position++;
    server_loop_queue->next_position =
        next_position % (server_loop_queue->len);
    return;
}

void init_server_loop_queue(char s_ip_array[MAX_S_NUM][MAX_LINE], size_t s_num,
                            server_loop_queue_t *server_loop_queue)
{
    size_t i = 0;
    for (i = 0; i < s_num; i++)
    {
        strncpy(server_loop_queue->server_array[i], s_ip_array[i], 15);
    }
    server_loop_queue->len = s_num;
    server_loop_queue->next_position = 0;

    return;
}
