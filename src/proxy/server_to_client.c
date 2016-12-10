/******************************************************************************
 *                                 Video CDN                                  *
 *                          15-641 Computer Network                           *
 *                             server_to_client.c                             *
 * This file contains function that can be used to send client response after *
 * getting video data from server.                                            *
 * Author: Qiaoyu Deng; Yangmei Lin                                           *
 * Andrew ID: qdeng; yangmeil                                                 *
 ******************************************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "server_to_client.h"
#include "constants.h"
#include "proxy.h"
#include "throughput.h"
#include "parse_manifest.h"

extern FILE *logfp;


/**
 * The video data received from server can be added into sending list, which
 * will then be free by sending function
 * @param  p        pool
 * @param  serverfd server's fd
 * @return          0 for success, nagetive for error
 */
int8_t s2c_list_read_server(pools_t *p, int serverfd)
{
    int clientfd = p->fd_s2c[serverfd];

    s2c_data_list_t *s2c_data_list_start = p->s2c_list[clientfd];
    if (s2c_data_list_start->next == NULL)
    {
        s2c_data_list_start->next = malloc(sizeof(s2c_data_list_t));
        memset(s2c_data_list_start->next, 0, sizeof(s2c_data_list_t));
    }
    s2c_data_list_t *s2c_data_rover =
        find_last_s2c_data(s2c_data_list_start);
    size_t read_offset = 0;
    size_t iter_count = 0;
    ssize_t read_ret = 0;
    do
    {
        iter_count++;
        char *data_start_ptr = s2c_data_rover->data + s2c_data_rover->len;
        size_t avail_data_space = BUF_SIZE - s2c_data_rover->len;
        read_ret = read(serverfd, data_start_ptr, avail_data_space);
        if (read_ret == 0)
        {
            if (avail_data_space == BUF_SIZE)
            {
                free(s2c_data_list_start->next);
                s2c_data_list_start->next = NULL;
            }
            Close_conn(serverfd, p);
            Close_conn(clientfd, p);
            return -1;
        }
        else if (read_ret < 0)
        {
            int errsv = errno;
            if (errsv != EAGAIN && errsv != EWOULDBLOCK)
            {
                Close_conn(serverfd, p);
                Close_conn(clientfd, p);
                return -2;
            }
            break;
        }
        else
        {
            s2c_data_rover->len += read_ret;
            if (s2c_data_rover->len == BUF_SIZE)
            {
                s2c_data_rover->next = malloc(sizeof(s2c_data_list_t));
                memset(s2c_data_rover->next, 0, sizeof(s2c_data_list_t));
                s2c_data_rover = s2c_data_rover->next;
            }
        }
    } while (iter_count < MAX_READ_ITER_COUNT);

    if (!FD_ISSET(clientfd, &p->active_wt_set))
    {
        FD_SET(clientfd, &p->active_wt_set);
    }

    return 0;
}


/**
 * Send data to client from sending list
 * @param  p        pool
 * @param  clientfd client's file descriptor
 * @return          0 for success, -1 for error
 */
int8_t s2c_list_write_client(pools_t *p, int clientfd)
{
    s2c_data_list_t *send2s_req_start = p->s2c_list[clientfd];
    s2c_data_list_t *rover = send2s_req_start->next;
    int serverfd = p->fd_c2s[clientfd];
    ssize_t write_ret = 0;
    int8_t ret = 0;
    size_t iter_cnt = 0;

    while (rover != NULL && iter_cnt <= MAX_WRIT_ITER_COUNT)
    {
        write_ret = write(clientfd, rover->data + rover->offset,
                          rover->len - rover->offset);
        if (write_ret > 0)
        {
            if (write_ret == rover->len - rover->offset)
            {
                send2s_req_start->next = rover->next;
                free(rover);
                rover = send2s_req_start->next;
            }
            else
            {
                rover->offset += write_ret;
            }
        }
        else if (write_ret < 0)
        {
            int errsv = errno;
            if (errsv == EWOULDBLOCK || errsv == EAGAIN)
            {
                break;
            }
            else
            {
                fprintf(logfp,
                        "Failed sending response to client from server, disconnected\n");
                Close_conn(clientfd, p);
                Close_conn(serverfd, p);
                return -1;
            }
        }
        else if (write == 0)
        {
            Close_conn(clientfd, p);
            Close_conn(serverfd, p);
            return 0;
        }
    }

    if (rover == NULL)
    {
        FD_CLR(clientfd, &p->active_wt_set);
    }

    return 0;
}

s2c_data_list_t *find_last_s2c_data(s2c_data_list_t *s2c_data)
{
    s2c_data_list_t *rover = s2c_data;
    while (rover->next != NULL)
    {
        rover = rover->next;
    }

    return rover;
}

