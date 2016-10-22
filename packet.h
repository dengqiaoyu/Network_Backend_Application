#ifndef _PACKET_H
#define _PACKET_H

#include <stdio.h>
#include <stdlib.h>
#include "constant.h"

typedef enum {WHOHAS, IHAVE, GET, DATA, ACK, DENIED} packet_type_code_enum;

typedef struct packet_sturct
{
    char magic_number[2];
    char version_number[1];
    char packet_type[1];
    char header_length[2];
    char total_packet_length[2];
    char sequence_number[4];
    char acknowldgment_number[4];
    char pay_load[PACKET_MAXSIZE - 16];
} packet_sturct;

#endif