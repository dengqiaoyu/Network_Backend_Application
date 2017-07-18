/******************************************************************************
 *                                 Video CDN                                  *
 *                          15-641 Computer Network                           *
 *                                  mydns.h                                   *
 * This file contains the declaration of all the functions used by proxy in   *
 * dns query.                                                                 *
 * Author: Qiaoyu Deng; Yangmei Lin                                           *
 * Andrew ID: qdeng; yangmeil                                                 *
 ******************************************************************************/
#include <netdb.h>
#include "proxy.h"

#define DNS_REQ_LEN 4144
#define UDP_RECV_BUFLEN 2000
#define DNS_SEND_BUFLEN 2000

int conn_dns_server(int port, dns_t * dns_info,pools_t *p);
void init_dns_msg_req(dns_msg_t *dns_msg);
dns_msg_list_t* form_dns_query(char *servername, dns_t * dns_info, int clientfd);
dns_msg_list_t* find_last_dns_req(dns_msg_list_t* dns_msg_list_h);
void get_hostname(Requests *reqs, char *hostname);
int conn_cli_server(dns_msg_t * dns_response, pools_t *p);
void send_first_req(pools_t *p, int clientfd);
int dns_process(dns_t * dns_info, pools_t *p);
void packet2net(dns_msg_t * dns_msg);
void packet2host(dns_msg_t * dns_msg);
char * form_qname(char *hostname);
void print_hex_str(char * msg_str, int len);
void parse_dns_msg(dns_msg_t *dns_msg,
                   char *recv_buf, size_t packet_len);
void print_dns_msg(dns_msg_t *dns_msg);
void bin2str(char *rdata, char *ip_addr);