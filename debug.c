/*
 * A debugging helper library.
 */

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <stdint.h>
#include "request.h"
#include "debug.h"

unsigned int debug = 0;

void binary2hex_dbg(uint8_t *buf, int len, char *hex);

struct debug_def {
    int debug_val;
    char *debug_def;
};

/*
 * This list is auto-generated and included at compile time.
 * To add things, edit debug.h
 */

static
struct debug_def debugs[] = {
#include "debug-text.h"
    { 0, NULL } /* End of list marker */
};

int set_debug(char *arg)
{
    int i;
    if (!arg || arg[0] == '\0') {
        return -1;
    }

    if (arg[0] == '?' || !strcmp(arg, "list")) {
        fprintf(stderr,
                "Debug values and definitions\n"
                "----------------------------\n");
        for (i = 0;  debugs[i].debug_def != NULL; i++) {
            fprintf(stderr, "%5d  %s\n", debugs[i].debug_val,
                    debugs[i].debug_def);
        }
        return -1;
    }

    if (isdigit(arg[0])) {
        debug |= atoi(arg);
    }
    return 0;
}

#ifdef _TEST_DEBUG_
int main() {
    if (set_debug("?") != -1) {
        fprintf(stderr, "set_debug(\"?\") returned wrong result code\n");
    }
    exit(0);
}

#endif

/* Packet debugging utilities */

void printf_packet(packet_sturct *packet)
{
    printf("magic_number:%hu\n",
           *(unsigned short*)packet->magic_number);
    printf("version_number:%d\n",
           *(char *)packet->version_number);
    printf("packet_type:%d\n",
           *(char *)packet->packet_type);
    printf("header_length:%hu\n",
           *(unsigned short*)packet->header_length);
    printf("total_packet_length:%hu\n",
           *(unsigned short*)packet->total_packet_length);
    printf("sequence_number:%u\n",
           *(unsigned int*)packet->sequence_number);
    printf("acknowldgment_number:%u\n",
           *(unsigned int*)packet->acknowldgment_number);
    char chunk_num = *(char *)packet->pay_load;
    printf("chunk_num:%d\n", chunk_num);
    int i = 0;
    for (i = 0; i < chunk_num; i++)
    {
        char buf[41] = {0};
        binary2hex_dbg((uint8_t *)packet->pay_load + 4 + i * 20,
                       20, buf);
        printf("chunk hash:%s\n", buf);
    }
}

void printf_requests(request_struct *request)
{
    printf("get_chunk_file:%s\n", request->get_chunk_file);
    printf("out_put_file:%s\n", request->out_put_file);
    request_item_struct *rover = request->whohas_ptr->next;
    while (rover)
    {
        printf("############################################\n");
        printf("peer_addr: %s\n", rover->peer_addr);
        printf("peer_port: %hu\n", rover->peer_port);
        printf("magic_number:%hu\n",
               *(unsigned short*)rover->packet_ptr->magic_number);
        printf("version_number:%d\n",
               *(char *)rover->packet_ptr->version_number);
        printf("packet_type:%d\n",
               *(char *)rover->packet_ptr->packet_type);
        printf("header_length:%hu\n",
               *(unsigned short*)rover->packet_ptr->header_length);
        printf("total_packet_length:%hu\n",
               *(unsigned short*)rover->packet_ptr->total_packet_length);
        printf("sequence_number:%u\n",
               *(unsigned int*)rover->packet_ptr->sequence_number);
        printf("acknowldgment_number:%u\n",
               *(unsigned int*)rover->packet_ptr->acknowldgment_number);
        char chunk_num = *(char *)rover->packet_ptr->pay_load;
        printf("chunk_num:%d\n", chunk_num);
        int i = 0;
        for (i = 0; i < chunk_num; i++)
        {
            char buf[41] = {0};
            binary2hex_dbg((uint8_t *)rover->packet_ptr->pay_load + 4 + i * 20,
                           20, buf);
            printf("chunk hash:%s\n", buf);
        }
        rover = rover->next;
    }
    rover = request->get_ptr->next;
    while (rover)
    {
        printf("############################################\n");
        printf("peer_addr: %s\n", rover->peer_addr);
        printf("peer_port: %hu\n", rover->peer_port);
        printf("magic_number:%hu\n",
               *(unsigned short*)rover->packet_ptr->magic_number);
        printf("version_number:%d\n",
               *(char *)rover->packet_ptr->version_number);
        printf("packet_type:%d\n",
               *(char *)rover->packet_ptr->packet_type);
        printf("header_length:%hu\n",
               *(unsigned short*)rover->packet_ptr->header_length);
        printf("total_packet_length:%hu\n",
               *(unsigned short*)rover->packet_ptr->total_packet_length);
        printf("sequence_number:%u\n",
               *(unsigned int*)rover->packet_ptr->sequence_number);
        printf("acknowldgment_number:%u\n",
               *(unsigned int*)rover->packet_ptr->acknowldgment_number);
        char chunk_num = *(char *)rover->packet_ptr->pay_load;
        printf("chunk_num:%d\n", chunk_num);
        int i = 0;
        for (i = 0; i < chunk_num; i++)
        {
            char buf[41] = {0};
            binary2hex_dbg((uint8_t *)rover->packet_ptr->pay_load + 4 + i * 20,
                           20, buf);
            printf("chunk hash:%s\n", buf);
        }
        rover = rover->next;
    }
}

void printf_responses(response_struct *response)
{
    response_item_struct *rover = response->whohas_ptr->next;
    while (rover)
    {
        printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
        printf("peer_addr: %s\n", rover->peer_addr);
        printf("peer_port: %hu\n", rover->peer_port);
        printf("magic_number:%hu\n",
               *(unsigned short*)rover->packet_ptr->magic_number);
        printf("version_number:%d\n",
               *(char *)rover->packet_ptr->version_number);
        printf("packet_type:%d\n",
               *(char *)rover->packet_ptr->packet_type);
        printf("header_length:%hu\n",
               *(unsigned short*)rover->packet_ptr->header_length);
        printf("total_packet_length:%hu\n",
               *(unsigned short*)rover->packet_ptr->total_packet_length);
        printf("sequence_number:%u\n",
               *(unsigned int*)rover->packet_ptr->sequence_number);
        printf("acknowldgment_number:%u\n",
               *(unsigned int*)rover->packet_ptr->acknowldgment_number);
        char chunk_num = *(char *)rover->packet_ptr->pay_load;
        printf("chunk_num:%d\n", chunk_num);
        int i = 0;
        for (i = 0; i < chunk_num; i++)
        {
            char buf[41] = {0};
            binary2hex_dbg((uint8_t *)rover->packet_ptr->pay_load + 4 + i * 20,
                           20, buf);
            printf("chunk hash:%s\n", buf);
        }
        rover = rover->next;
    }
}

void binary2hex_dbg(uint8_t *buf, int len, char *hex)
{
    int i = 0;
    for (i = 0; i < len; i++) {
        sprintf(hex + (i * 2), "%.2x", buf[i]);
    }
    hex[len * 2] = 0;
}