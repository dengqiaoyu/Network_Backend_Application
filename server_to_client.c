#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "server_to_client.h"
#include "constants.h"
#include "proxy.h"

extern FILE *logfp;

uint8_t s2c_list_read_server(pools_t *p, int serverfd)
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
        // dbg_cp3_p3_printf("avail_data_space: %ld\n", avail_data_space);
        read_ret = read(serverfd, data_start_ptr, avail_data_space);
        // dbg_cp3_p3_printf("read_ret in s2c_list_read_server: %ld\n", read_ret);
        if (read_ret == 0)
        {
            Close_conn(serverfd, p);
            return -1;
        }
        else if (read_ret < 0)
        {
            int errsv = errno;
            if (errsv != EAGAIN && errsv != EWOULDBLOCK)
            {
                Close_conn(serverfd, p);
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

uint8_t s2c_list_write_client(pools_t *p, int clientfd)
{
    // dbg_cp3_p3_printf("entering s2c_list_write_client\n");
    s2c_data_list_t *send2s_req_start = p->s2c_list[clientfd];
    s2c_data_list_t *rover = send2s_req_start->next;
    int serverfd = p->fd_c2s[clientfd];
    ssize_t write_ret = 0;
    int8_t ret = 0;
    size_t iter_cnt = 0;

    // dbg_cp3_p3_printf("line 72\n");
    while (rover != NULL && iter_cnt <= MAX_WRIT_ITER_COUNT)
    {
        write_ret = write(clientfd, rover->data + rover->offset,
                          rover->len - rover->offset);
        // dbg_cp3_p3_printf("write_ret in line 77: %ld\n", write_ret);
        if (write_ret > 0)
        {
            // dbg_cp3_p3_printf("\n----writing to client----\n");
            // // printf("%s", rover->data + rover->offset);
            // printf("len: %ld\n", rover->len);
            // printf("write_ret: %ld\n", write_ret);
            // dbg_cp3_p3_printf("\n----writing to client----\n");
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
    // dbg_cp3_p3_printf("exiting s2c_list_write_client\n");
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

