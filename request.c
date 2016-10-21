#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include "request.h"
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
inline void set_ip_port(request_item_struct *request_item, char *peer_addr,
                        unsigned short peer_port);
inline void init_packet(request_item_struct *request_item);

ssize_t init_whohas_request(request_struct *request)
{
    ssize_t ret = 0;

    FILE *plist_file = NULL;
    char node_info[NODE_LINE_MAXSIZE + 1] = {0};
    plist_file = fopen(config.peer_list_file, "r");
    if (plist_file == NULL)
    {
        printf("peer-list-file does not exist\n");
        return -1;
    }

    FILE *chunks_file = NULL;
    char target_chunk[HASH_LINE_MAXSIZE + 1] = {0};
    chunks_file = fopen(request->get_chunk_file, "r");
    if (chunks_file == NULL)
    {
        printf("chunk-file does not exist\n");
        return -1;
    }

    while (fgets(node_info, NODE_LINE_MAXSIZE, plist_file) != NULL)
    {
        size_t peer_id = 0;
        char peer_addr[16] = {0};
        unsigned short peer_port = -1;
        ret = sscanf(node_info, "%ld %16s %hu\n",
                     &peer_id, peer_addr, &peer_port);
        if (ret == 0)
        {
            continue;
        }
        dbg_cp1_printf("After parse: %ld %s %hu\n",
                       peer_id, peer_addr, peer_port);

        size_t pay_load_len = 0;
        while (fgets(target_chunk, HASH_LINE_MAXSIZE, chunks_file) != NULL)
        {
            pay_load_len += 20;
        }
        fseek(chunks_file, 0, SEEK_SET);
        char *pay_load = malloc(pay_load_len + 1);
        memset(pay_load, 0, pay_load_len + 1);
        size_t pay_load_offset = 0;
        while (fgets(target_chunk, HASH_LINE_MAXSIZE, chunks_file) != NULL)
        {
            size_t chunk_id = 0;
            char hash_str[HASH_LEN + 1] = {0};
            ret = sscanf(target_chunk, "%ld %40s\n", &chunk_id, hash_str);
            if (ret == 0)
            {
                continue;
            }
            dbg_cp1_printf("Want: %ld %s\n", chunk_id, hash_str);
            hex2binary(hash_str, 40, (uint8_t*)pay_load + pay_load_offset);
            pay_load_offset += 20;
        }
        add_whohas_packet(request, peer_addr, peer_port,
                          pay_load, pay_load_len);
        free(pay_load);
        fseek(chunks_file, 0, SEEK_SET);
    }

    fclose(plist_file);
    plist_file = NULL;
    fclose(chunks_file);
    chunks_file = NULL;
    return 0;
}

ssize_t add_whohas_packet(request_struct *request, char *peer_addr,
                          unsigned short peer_port, char *pay_load,
                          unsigned short pay_load_len)
{
    request_item_struct *last = request->whohas_ptr;
    unsigned short pay_load_offset = 0;
    do
    {
        last = find_last_req_ptr(last);
        last->next = malloc(sizeof(request_item_struct));
        memset(last->next, 0, sizeof(request_item_struct));
        set_ip_port(last->next, peer_addr, peer_port);
        init_packet(last->next);
        if (pay_load_len > (PACKET_MAXSIZE - 20))
        {
            unsigned short *total_packet_length =
                (unsigned short *)last->next->packet_ptr->total_packet_length;
            *total_packet_length = PACKET_MAXSIZE;
            char *chunk_num = (char *)last->next->packet_ptr + 16;
            *chunk_num = (PACKET_MAXSIZE - 20) / 20;
            strncpy(last->next->packet_ptr->pay_load + 4,
                    pay_load + pay_load_offset, (PACKET_MAXSIZE - 20));
            pay_load_offset += (PACKET_MAXSIZE - 20);
            pay_load_len -= (PACKET_MAXSIZE - 20);
        }
        else
        {
            unsigned short *total_packet_length =
                (unsigned short *)last->next->packet_ptr->total_packet_length;
            *total_packet_length = pay_load_len + 20;
            char *chunk_num = (char *)last->next->packet_ptr + 16;
            *chunk_num = pay_load_len / 20;
            strncpy(last->next->packet_ptr->pay_load + 4,
                    pay_load + pay_load_offset, pay_load_len);
            pay_load_offset = pay_load_len;
            pay_load_len = 0;
        }
    } while (pay_load_len > (PACKET_MAXSIZE - 20));
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

inline void set_ip_port(request_item_struct *request_item, char *peer_addr,
                        unsigned short peer_port)
{
    strncpy(request_item->peer_addr, peer_addr, 16);
    request_item->peer_port = peer_port;
}

inline void init_packet(request_item_struct *request_item)
{
    request_item->packet_ptr = malloc(sizeof(packet_sturct));
    memset(request_item->packet_ptr, 0, sizeof(packet_sturct));
    *((unsigned short *)request_item->packet_ptr->magic_number) =
        (unsigned short)15441;
    *((unsigned short *)request_item->packet_ptr->version_number) =
        (unsigned short)1;
    *((unsigned short *)request_item->packet_ptr->header_length) =
        (unsigned short)16;
    *((unsigned short *)request_item->packet_ptr->total_packet_length) =
        (unsigned short)16;
    *((unsigned int *)request_item->packet_ptr->sequence_number) =
        (unsigned int)(4294967295);
    *((unsigned int *)request_item->packet_ptr->acknowldgment_number) =
        (unsigned int)(4294967295);
}

inline void add2sending_list(request_item_struct *request_item,
                             item_to_send_struct *sending_list)
{
    sending_list->next = request_item->next;
    request_item->next = NULL;
}

ssize_t send_request(int sock, item_to_send_struct *sending_list)
{
    ssize_t writeret = 0;
    item_to_send_struct *rover_last = sending_list;
    item_to_send_struct *rover = sending_list->next;
    while (rover != NULL)
    {
        dbg_cp1_printf("sending packets...\n");
        struct sockaddr_in addr;
        bzero(&addr, sizeof(addr));
        inet_pton(AF_INET, rover->peer_addr, &addr);
        addr.sin_family = AF_INET;
        addr.sin_port = htons(rover->peer_port);
        unsigned short packet_len =
            *((unsigned short *)rover->packet_ptr->total_packet_length);
        writeret = sendto(sock, rover->packet_ptr, packet_len, 0,
                          (struct sockaddr *)&addr, sizeof(addr));
        if (writeret == -1)
        {
            int errsv = errno;
            if (errsv == EAGAIN || errno == EWOULDBLOCK)
            {
                break;
            }
            else
            {
                printf("error: %s\n", strerror(errsv));
                return -1;
            }
        }
        else
        {
            if (writeret != packet_len)
            {
                break;
            }
            else
            {
                rover_last->next = rover->next;
                free(rover->packet_ptr);
                free(rover);
                rover = rover_last->next;
            }
        }
    }
    if (sending_list->next != NULL)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}