#ifndef DNS_H
#define DNS_H

#include <stdio.h>
#include <stdlib.h>

#define QNAME_LEN 256
#define RDATA_LEN 1024

typedef struct dns_qst_t_s
{
    char qname[QNAME_LEN];
    uint16_t qname_len;
    int16_t qtype;
    int16_t qclass;
} dns_qst_t;

typedef struct dns_rr_t_s
{
    char name[QNAME_LEN];
    uint16_t name_len;
    uint16_t type;
    uint16_t class_t;
    uint32_t ttl;
    uint16_t rdlength;
    char rdata[RDATA_LEN];
} dns_rr_t;

typedef struct dns_msg_t_s
{
    uint16_t id;
    unsigned char rd: 1;
    unsigned char tc: 1;
    unsigned char aa: 1;
    unsigned char opcode: 4;
    unsigned char qr: 1;
    unsigned char rcode: 4;
    unsigned char z: 3;
    unsigned char ra: 1;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
    dns_qst_t question;
    dns_rr_t answer;
    dns_rr_t authority;
    dns_rr_t additional;
} dns_msg_t;

typedef struct dns_msg_list_t_s
{
    dns_msg_t *dns_msg;
    struct dns_msg_list_t_s *next;
} dns_msg_list_t;

typedef struct dns_t_s
{
    int cur_id;
    int dns_sock;
    int client_stat[FD_SETSIZE];//-1 no connection,0 connect but not resolve,
    //1 dns request formed; 2 dns request sentout; 3 resolve success;
    int dnsid_client[FD_SETSIZE];
    // fd_set active_rd_set;
    // fd_set active_wt_set;
    fd_set read_set;
    fd_set write_set;
    dns_msg_list_t *dns_msg_list;
} dns_t;

#endif