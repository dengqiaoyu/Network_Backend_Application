/******************************************************************************
 *                                 Video CDN                                  *
 *                          15-641 Computer Network                           *
 *                                nameserver.h                                *
 * This file contains header file for nameserver.c                            *
 * Author: Qiaoyu Deng; Yangmei Lin                                           *
 * Andrew ID: qdeng; yangmeil                                                 *
 ******************************************************************************/

#ifndef NAMESERVER_H
#define NAMESERVER_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "hashtable.h"
#include "round_robin.h"
#include "dns.h"

#define MAX_LINE 1024
#define RECV_BUF_LEN 8192
#define DNS_MSG_NET_LEN 8192

typedef struct nameserver_param_s
{
    uint8_t is_round_robin;
    char log_path[MAX_LINE];
    char dns_ip[16];
    char dns_port[6];
    char servers_path[MAX_LINE];
    char lsas_path[MAX_LINE];
} nameserver_param_t;

uint8_t get_argv(int argc, char **argv, nameserver_param_t *nameserver_param);
hashtable_t *init_dns(server_loop_queue_t *server_loop_queue,
                      nameserver_param_t *nameserver_param);
int open_listenfd_withip(char *ip, char *port);
void parse_dns_msg(dns_msg_t *dns_msg,
                   char *recv_buf, size_t packet_len);
void get_url(char *qname, size_t qname_len, char *url);
size_t form_response(dns_msg_t *dns_msg, char *dns_msg_net,
                     uint8_t if_correct, char *server_ip);
void str2bin(char *server_ip, char *ip_address_bin);
void print_dns_msg(dns_msg_t *dns_msg);
#endif