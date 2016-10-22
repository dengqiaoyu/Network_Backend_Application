#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "bt_parse.h"
#include "constant.h"
#include "packet.h"
#include "request.h"
#include "response.h"
#include "send.h"
#include "chunk.h"
#include "jwHash.h"
#include "debug.h"

extern bt_config_t config;

response_struct *init_response_list()
{
    response_struct *response_list = malloc(sizeof(response_struct));
    memset(response_list, 0, sizeof(response_struct));
    response_list->whohas_ptr = malloc(sizeof(response_item_struct));
    return response_list;
}

inline char get_packet_type(packet_sturct *packet)
{
    return *packet->packet_type;
}

inline unsigned short get_packet_len(packet_sturct *packet)
{
    return *(unsigned short *)packet->total_packet_length;
}

ssize_t init_responses(response_struct *response_list, char *buf,
                       unsigned short buflen,
                       char *peer_addr, unsigned short peer_port)
{
    unsigned short bufoffset = 0;
    response_item_struct *last_whohas =
        find_last_rep_ptr(response_list->whohas_ptr);
    while (bufoffset < buflen)
    {
        char packet_type = get_packet_type((packet_sturct *)(buf + bufoffset));
        unsigned short packet_len =
            get_packet_len((packet_sturct *)(buf + bufoffset));
        dbg_cp1_printf("packet_type: %d, packet_len: %hu\n",
                       packet_type, packet_len);
        if (packet_len > buflen - bufoffset)
        {
            return -1;
        }
        switch ((int)packet_type)
        {
        case 0: // WHOHAS
            dbg_cp1_printf("Entering WHOHAS\n");
            last_whohas->next = malloc(sizeof(response_item_struct));
            last_whohas = last_whohas->next;
            memset(last_whohas, 0, sizeof(response_item_struct));
            strncpy(last_whohas->peer_addr, peer_addr, 16);
            last_whohas->peer_port = peer_port;
            last_whohas->packet_ptr = malloc(packet_len);
            memset(last_whohas->packet_ptr, 0, packet_len);
            memcpy(last_whohas->packet_ptr, (packet_sturct *)buf + bufoffset,
                   packet_len);
            break;
        case 1:
            dbg_cp1_printf("Entering IHAS\n");
            break;
        case 2:
            break;
        case 3:
            break;
        case 4:
            break;
        case 5:
            break;
        default:
            break;
        }
        bufoffset += packet_len;
    }

    return 0;
}

ssize_t process_request(response_struct *response_list,
                        packet2send_sturct *sending_list,
                        jwHashTable *haschunk_hash_table)
{
    response_item_struct *whohas_rover_last = response_list->whohas_ptr;
    response_item_struct *whohas_rover = whohas_rover_last->next;
    dbg_cp1_printf("process_request start!!!!!!!!!!!!!!!!\n");
    while (whohas_rover != NULL)
    {
        packet2send_sturct *packet2send = get_ihave_response(whohas_rover,
                                          haschunk_hash_table);
        if (packet2send != NULL)
        {
            packet_add2sending_list(packet2send, sending_list);
            printf_packet(packet2send->packet_ptr);
        }

        whohas_rover_last->next = whohas_rover->next;
        free(whohas_rover->packet_ptr);
        free(whohas_rover);
        whohas_rover = whohas_rover_last->next;
    }
    return 0;
}

packet2send_sturct *get_ihave_response(response_item_struct *response_item,
                                       jwHashTable *haschunk_hash_table)
{
    packet2send_sturct *ihave = NULL;
    unsigned short *total_packet_length = NULL;
    char *ihave_chunk_num = NULL;
    unsigned short ihave_pay_load_offset = 0;
    char *ihave_pay_load = NULL;
    char *response_pay_load = response_item->packet_ptr->pay_load;
    char response_chunk_num = *response_pay_load;
    char i;
    for (i = 0; i < response_chunk_num; i++)
    {
        char chunk_hash_hex[41] = {0};
        binary2hex((uint8_t *)response_pay_load + 4 + i * 20, 20,
                   chunk_hash_hex);
        //printf("chunk hash hex:%s\n", chunk_hash_hex);
        int chunk_id = 0;
        HASHRESULT hash_result = get_int_by_str(haschunk_hash_table,
                                                chunk_hash_hex, &chunk_id);
        if (hash_result == HASHOK)
        {
            if (ihave == NULL)
            {
                ihave = malloc(sizeof(packet2send_sturct));
                memset(ihave, 0, sizeof(packet2send_sturct));

                set_ip_port(ihave, response_item->peer_addr,
                            response_item->peer_port);
                ihave->packet_ptr = init_packet();
                *(ihave->packet_ptr->packet_type) = 1;
                total_packet_length =
                    (unsigned short *)ihave->packet_ptr->total_packet_length;
                ihave_chunk_num = ihave->packet_ptr->pay_load;
                ihave_pay_load = ihave->packet_ptr->pay_load;
                *total_packet_length = 40;
                *ihave_chunk_num = 1;
                ihave_pay_load_offset = 4;
                memcpy(ihave_pay_load + ihave_pay_load_offset,
                       response_pay_load + 4 + i * 20, 20);
                ihave_pay_load_offset += 20;
            }
            else
            {
                *ihave_chunk_num = *ihave_chunk_num + 1;
                *total_packet_length += 20;
                memcpy(ihave_pay_load + ihave_pay_load_offset,
                       response_pay_load + 4 + i * 20, 20);
                ihave_pay_load_offset += 20;
            }
        }
    }

    return ihave;
}

void packet_add2sending_list(packet2send_sturct *packet2send,
                             packet2send_sturct *sending_list)
{
    packet2send_sturct *last = find_last_send_ptr(sending_list);
    last->next = packet2send;
    packet2send->next = NULL;
}

inline response_item_struct *find_last_rep_ptr(response_item_struct *item_ptr)
{
    response_item_struct *rover = item_ptr;
    while (rover->next != NULL)
    {
        rover = rover->next;
    }
    return rover;
}