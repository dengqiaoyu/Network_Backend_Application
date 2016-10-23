#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include "hashtable.h"
#include "request.h"
#include "send.h"
#include "bt_parse.h"
#include "debug.h"
#include "chunk.h"


extern bt_config_t config;

ssize_t add_whohas_packet(request_struct *request, char *peer_addr,
                          unsigned short peer_port, char *pay_load,
                          unsigned short pay_load_len);
inline void init_request(request_struct *request);
inline void set_packet(request_item_struct *request_item);
inline request_item_struct *find_last_req_ptr(request_item_struct *item_ptr);

peer_list_struct *init_peer_list()
{
    ssize_t ret = 0;
    peer_list_struct *peer_list = malloc(sizeof(peer_list_struct));
    memset(peer_list, 0, sizeof(peer_list_struct));
    peer_list_struct *last = peer_list;
    FILE *plist_fptr = fopen(config.peer_list_file, "r");
    if (plist_fptr == NULL)
    {
        printf("peer-list-file does not exist\n");
        return NULL;
    }
    char plist_line[PEER_LIST_MAXSIZE];

    while (fgets(plist_line, PEER_LIST_MAXSIZE, plist_fptr) != NULL)
    {
        last->next = malloc(sizeof(peer_list_struct));
        memset(last->next, 0, sizeof(peer_list_struct));

        ret = sscanf(plist_line, "%ld %16s %hu\n",
                     &(last->next->peer_id),
                     last->next->peer_addr,
                     &(last->next->peer_port));
        if (ret == 0)
        {
            free(last->next);
            last->next = NULL;
            continue;
        }

        if (last->next->peer_id == config.identity)
        {
            free(last->next);
            last->next = NULL;
            continue;
        }
        last = last->next;
    }

    last = peer_list;
    peer_list = last->next;
    free(last);

    return peer_list;
}

ssize_t init_whohas_request(request_struct *request,
                            peer_list_struct *peer_list)
{
    ssize_t ret = 0;

    FILE *chunks_file = NULL;
    char target_chunk_line[HASH_LINE_MAXSIZE + 1] = {0};
    chunks_file = fopen(request->get_chunk_file, "r");
    if (chunks_file == NULL)
    {
        printf("chunk-file does not exist\n");
        return -1;
    }

    size_t pay_load_len = 4;
    while (fgets(target_chunk_line, HASH_LINE_MAXSIZE, chunks_file) != NULL)
    {
        pay_load_len += 20;
    }

    fseek(chunks_file, 0, SEEK_SET);
    char *pay_load = malloc(pay_load_len);
    char *chunk_num = pay_load;
    memset(pay_load, 0, pay_load_len);
    *chunk_num = 0;
    size_t pay_load_offset = 4;
    while (fgets(target_chunk_line, HASH_LINE_MAXSIZE, chunks_file) != NULL)
    {
        *chunk_num += 1;
        size_t chunk_id = -1;
        char hash_str[41] = {0};
        ret = sscanf(target_chunk_line, "%ld %40s\n", &chunk_id, hash_str);
        if (ret == 0)
        {
            continue;
        }
        dbg_cp1_printf("Want: %ld %s\n", chunk_id, hash_str);
        hex2binary(hash_str, 40, (uint8_t*)(pay_load + pay_load_offset));
        pay_load_offset += 20;
    }
    fclose(chunks_file);

    // dbg_cp1_printf("================================\n");
    // printf_pay_load(pay_load);
    // dbg_cp1_printf("================================\n");

    peer_list_struct *rover = peer_list;
    while (rover != NULL)
    {
        dbg_cp1_printf("prepare plan for %s: %d\n", rover->peer_addr,
                       rover->peer_port);
        add_whohas_packet(request, rover->peer_addr, rover->peer_port,
                          pay_load, pay_load_len);
        rover = rover->next;
    }
    free(pay_load);
    chunks_file = NULL;
    return 0;
}

ssize_t add_whohas_packet(request_struct *request, char *peer_addr,
                          unsigned short peer_port, char *pay_load,
                          unsigned short pay_load_len)
{
    request_item_struct *last = find_last_req_ptr(request->whohas_ptr);
    unsigned short pay_load_offset = 0;
    do
    {
        last->next = malloc(sizeof(request_item_struct));
        last = last->next;
        memset(last, 0, sizeof(request_item_struct));
        set_ip_port((packet2send_sturct *)last, peer_addr, peer_port);
        last->packet_ptr = init_packet();
        *(last->packet_ptr->packet_type) = 0;
        if (pay_load_len > (PACKET_MAXSIZE - 16))
        {
            unsigned short *total_packet_length =
                (unsigned short *)last->packet_ptr->total_packet_length;
            *total_packet_length = PACKET_MAXSIZE;
            memcpy(last->packet_ptr->pay_load,
                   pay_load + pay_load_offset, (PACKET_MAXSIZE - 16));
            pay_load_offset += (PACKET_MAXSIZE - 16);
            pay_load_len -= (PACKET_MAXSIZE - 16);
        }
        else
        {
            unsigned short *total_packet_length =
                (unsigned short *)last->packet_ptr->total_packet_length;
            *total_packet_length = pay_load_len + 16;
            memcpy(last->packet_ptr->pay_load,
                   pay_load + pay_load_offset, pay_load_len);
            pay_load_offset = pay_load_len;
            pay_load_len = 0;
        }
    } while (pay_load_len > (PACKET_MAXSIZE - 16));

    return 0;
}

void init_request(request_struct *request)
{
    bzero(request, sizeof(*request));
    request->whohas_ptr = malloc(sizeof(request_item_struct));
    request->get_ptr = malloc(sizeof(request_item_struct));
    memset(request->whohas_ptr, 0, sizeof(request_item_struct));
    memset(request->get_ptr, 0, sizeof(request_item_struct));
}

inline request_item_struct *find_last_req_ptr(request_item_struct *item_ptr)
{
    request_item_struct *rover = item_ptr;
    while (rover->next != NULL)
    {
        rover = rover->next;
    }
    return rover;
}


inline void get_add2sending_list(request_item_struct *request_item,
                                 packet2send_sturct *sending_list)
{
    packet2send_sturct *last = find_last_send_ptr(sending_list);
    last->next = (packet2send_sturct *)request_item->next;
    request_item->next = NULL;
}
