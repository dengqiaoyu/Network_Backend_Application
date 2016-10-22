#ifndef _SEND_H
#define _SEND_H
#include <stdio.h>
#include <stdlib.h>
#include "constant.h"
#include "packet.h"
#include "request.h"
#include "response.h"

packet2send_sturct *init_sending_list();
ssize_t send_udp(int sock, packet2send_sturct *sending_list);
inline packet2send_sturct *find_last_send_ptr(packet2send_sturct *packet2send);
#endif