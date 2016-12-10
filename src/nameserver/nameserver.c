/******************************************************************************
 *                                 Video CDN                                  *
 *                          15-641 Computer Network                           *
 *                              nameserver.c                                  *
 * This file contains main funtion that execute a DNS server for load balance *
 * It blocks to read and write because it uses UDP                            *
 * Author: Qiaoyu Deng; Yangmei Lin                                           *
 * Andrew ID: qdeng; yangmeil                                                 *
 ******************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <errno.h>
#include <arpa/inet.h>
#include <time.h>
#include <errno.h>
#include "nameserver.h"
#include "dns.h"
#include "hashtable.h"
#include "graph.h"
#include "dijkstra.h"
#include "round_robin.h"

FILE *logfp = NULL;

int main(int argc, char **argv)
{
    int8_t ret = 0;
    nameserver_param_t nameserver_param;
    memset(&nameserver_param, 0, sizeof(nameserver_param_t));
    ret = get_argv(argc, argv, &nameserver_param);
    logfp = fopen(nameserver_param.log_path, "w");
    if (logfp == NULL)
    {
        printf("log file open failed. Exit\n");
        exit(1);
    }

    hashtable_t *c2s_ip_ht = NULL;
    server_loop_queue_t server_loop_queue;
    c2s_ip_ht = init_dns(&server_loop_queue, &nameserver_param);

    int sock = open_listenfd_withip(nameserver_param.dns_ip,
                                    nameserver_param.dns_port);
    if (sock == -1)
    {
        printf("open_listenfd_withip failed. Exit\n");
    }

    while (1)
    {
        ssize_t readret = 0;
        char recv_buf[RECV_BUF_LEN] = {0};
        struct sockaddr_in from;
        socklen_t fromlen;
        fromlen = sizeof(from);
        readret = recvfrom(sock, recv_buf, RECV_BUF_LEN, 0,
                           (struct sockaddr *) &from, &fromlen);
        char c_host[16] = {0};
        strncpy(c_host, inet_ntoa(from.sin_addr), 15);

        if (ret != 0)
        {
            fprintf(logfp, "Cannot resolve client ip\n");
            fflush(logfp);
            continue;
        }
        size_t packet_len = readret;
        dns_msg_t dns_msg;
        memset(&dns_msg, 0, sizeof(dns_msg_t));
        parse_dns_msg(&dns_msg, recv_buf, packet_len);
        char url[QNAME_LEN] = {0};
        get_url(dns_msg.question.qname, dns_msg.question.qname_len, url);
        uint8_t if_correct = 0;
        char server_ip[16] = {0};
        if (strncasecmp(url, "video.cs.cmu.edu", 16) == 0)
        {
            if_correct = 1;
            if (nameserver_param.is_round_robin == 1)
            {
                round_robin(&server_loop_queue, server_ip);
            }
            else
            {
                char *server_ip_ptr = ht_get(c2s_ip_ht,
                                             c_host, strlen(c_host), NULL);
                strncpy(server_ip, server_ip_ptr, 15);
            }
        }
        char dns_msg_net[DNS_MSG_NET_LEN] = {0};
        size_t msg_len = form_response(&dns_msg, dns_msg_net, if_correct,
                                       server_ip);
        dns_msg_t dns_msg_tmp;
        memset(&dns_msg_tmp, 0 , sizeof(dns_msg_t));
        parse_dns_msg(&dns_msg_tmp, dns_msg_net, msg_len);
        sendto(sock, dns_msg_net, msg_len, 0,
               (struct sockaddr *) &from, fromlen);
        fprintf(logfp, "%ld %s %s %s\n", time(NULL), c_host, url,
                server_ip);
        fflush(logfp);
    }
}

/**
 * get and check arguments
 * @param  nameserver_param return value
 * @return                  0 for success, -1 for error
 */
uint8_t get_argv(int argc, char **argv, nameserver_param_t *nameserver_param)
{
    uint8_t offset = 0;
    if (argc == 7)
    {
        if (strncmp(argv[1], "-r", 2) != 0)
        {
            return -1;
        }
        nameserver_param->is_round_robin = 1;
        offset++;
    }
    else if (argc == 6)
    {
        nameserver_param->is_round_robin = 0;
    }
    else
    {
        fprintf(stderr, "Usage: %s ", argv[0]);
        fprintf(stderr, "[-r] ");
        fprintf(stderr, "<log> ");
        fprintf(stderr, "<ip> ");
        fprintf(stderr, "<port> ");
        fprintf(stderr, "<servers> ");
        fprintf(stderr, "<LSAs> ");
        fflush(stderr);
        return -1;
    }

    if (strlen(argv[offset + 1]) > MAX_LINE)
    {
        return -1;
    }
    else
    {
        strncpy(nameserver_param->log_path, argv[offset + 1], MAX_LINE);
    }

    if (strlen(argv[offset + 2]) > 15)
    {
        return -1;
    }
    else
    {
        strncpy(nameserver_param->dns_ip, argv[offset + 2], 15);
    }

    if (strlen(argv[offset + 3]) > 6)
    {
        return -1;
    }
    else
    {
        strncpy(nameserver_param->dns_port, argv[offset + 3], 6);
    }

    if (strlen(argv[offset + 4]) > MAX_LINE)
    {
        return -1;
    }
    else
    {
        strncpy(nameserver_param->servers_path, argv[offset + 4], MAX_LINE);
    }

    if (strlen(argv[offset + 5]) > MAX_LINE)
    {
        return -1;
    }
    else
    {
        strncpy(nameserver_param->lsas_path, argv[offset + 5], MAX_LINE);
    }

    return 0;
}

/**
 * initialize dns, and compute dijstra distance, assigning each client a server
 * @param  server_loop_queue struct that saves information for how many times
 *                           the server has been choosed
 * @param  nameserver_param
 * @return                   hashtable used to assign server IP
 */
hashtable_t *init_dns(server_loop_queue_t *server_loop_queue,
                      nameserver_param_t *nameserver_param)
{
    size_t i = 0;
    size_t s_num = 0;
    char line[MAX_LINE] = {0};
    hashtable_t *c2s_ip_ht = NULL;

    char s_ip_array[MAX_S_NUM][MAX_LINE];
    FILE *server_file = fopen(nameserver_param->servers_path, "r");
    for (i = 0; i < MAX_S_NUM; i++)
    {
        memset(s_ip_array[i], 0, MAX_LINE);
    }
    while (fgets(line, 1023, server_file) != NULL)
    {
        sscanf(line, "%s\n", s_ip_array[s_num]);
        s_num++;
    }
    fclose(server_file);

    if (nameserver_param->is_round_robin == 1)
    {
        init_server_loop_queue(s_ip_array, s_num, server_loop_queue);
        c2s_ip_ht = NULL;
    }
    else
    {
        memset(line, 0, MAX_LINE);
        FILE *lsa_file = fopen(nameserver_param->lsas_path, "r");
        graph_t *graph = init_graph();
        while (fgets(line, 1023, lsa_file) != NULL)
        {
            lsa_msg_t lsa_msg;
            parse_lsa_line(&lsa_msg, line);
            update_graph(graph, &lsa_msg);
        }
        fclose(lsa_file);

        c2s_ip_ht = ht_create(0, 1024, NULL);
        dijkstra(graph, c2s_ip_ht, s_ip_array, s_num);
        destroy_graph(graph);
    }

    return c2s_ip_ht;
}

/**
 * Use fake IP to create a fd to listen and send data
 * @param  ip   fake ip
 * @param  port communication port
 * @return      fd
 */
int open_listenfd_withip(char *ip, char *port)
{
    //SOCK_DGRAM
    int8_t ret = 0;
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in localaddr;
    localaddr.sin_family = AF_INET;
    localaddr.sin_addr.s_addr = inet_addr(ip);
    localaddr.sin_port = htons(atoi(port));

    ret = bind(sockfd, (struct sockaddr *)&localaddr, sizeof(localaddr));
    if (ret == -1)
    {
        int errsv = errno;
        printf("%s\n", strerror(errsv));
        fprintf(logfp, "%s\n", strerror(errsv));
        return -1;
    }

    return sockfd;
}

/**
 * parse the text message into struct
 * @param dns_msg    [description]
 * @param recv_buf   text message pointer
 * @param packet_len the length of text message
 */
void parse_dns_msg(dns_msg_t *dns_msg,
                   char *recv_buf, size_t packet_len)
{
    uint16_t id_network = *((uint16_t *)recv_buf);
    uint16_t id_host = ntohs(id_network);
    memcpy(dns_msg, &id_host, sizeof(uint16_t));

    memcpy((char *)dns_msg + 2, recv_buf + 2, sizeof(uint16_t));

    uint16_t qdcount_network = *((uint16_t *)(recv_buf + 4));
    uint16_t qdcount_host = ntohs(qdcount_network);
    memcpy(&dns_msg->qdcount, &qdcount_host, sizeof(uint16_t));

    uint16_t ancount_network = *((uint16_t *)(recv_buf + 6));
    uint16_t ancount_host = ntohs(ancount_network);
    memcpy(&dns_msg->ancount, &ancount_host, sizeof(uint16_t));

    uint16_t nscount_network = *((uint16_t *)(recv_buf + 8));
    uint16_t nscount_host = ntohs(nscount_network);
    memcpy(&dns_msg->nscount, &nscount_host, sizeof(uint16_t));

    uint16_t arcount_network = *((uint16_t *)(recv_buf + 10));
    uint16_t arcount_host = ntohs(arcount_network);
    memcpy(&dns_msg->arcount, &arcount_host, sizeof(uint16_t));

    char *qname = recv_buf + 12;
    size_t i = 0;
    while (qname[i] != 0)
    {
        i++;
    }
    uint16_t qname_len = (uint16_t)(i + 1);
    dns_msg->question.qname_len = qname_len;
    memcpy(dns_msg->question.qname, qname, qname_len);

    uint16_t qtype_network = *((uint16_t *)(recv_buf + 12 + qname_len));
    uint16_t qtype_host = ntohs(qtype_network);
    memcpy(&dns_msg->question.qtype, &qtype_host, sizeof(uint16_t));

    uint16_t qclass_network = *((uint16_t *)(recv_buf + 14 + qname_len));
    uint16_t qclass_host = ntohs(qclass_network);
    memcpy(&dns_msg->question.qclass, &qclass_host, sizeof(uint16_t));

    if (dns_msg->qr == 0)
    {
        return;
    }

    char *name = recv_buf + 16 + qname_len;
    i = 0;
    while (name[i] != 0)
    {
        i++;
    }
    uint16_t name_len = (uint16_t)(i + 1);
    dns_msg->answer.name_len = name_len;
    memcpy(dns_msg->answer.name, name, name_len);

    uint16_t type_network =
        *((uint16_t *)(recv_buf + 16 + qname_len + name_len));
    uint16_t type_host = ntohs(type_network);
    memcpy(&dns_msg->answer.type, &type_host, sizeof(uint16_t));

    uint16_t class_t_network =
        *((uint16_t *)(recv_buf + 18 + qname_len + name_len));
    uint16_t class_t_host = ntohs(class_t_network);
    memcpy(&dns_msg->answer.class_t, &class_t_host, sizeof(uint16_t));

    uint32_t ttl_network =
        *((uint32_t *)(recv_buf + 20 + qname_len + name_len));
    uint32_t ttl_host = ntohl(ttl_network);
    memcpy(&dns_msg->answer.ttl, &ttl_host, sizeof(uint32_t));

    uint16_t rdlength_network =
        *((uint16_t *)(recv_buf + 24 + qname_len + name_len));
    uint16_t rdlength_host = ntohs(rdlength_network);
    memcpy(&dns_msg->answer.rdlength, &rdlength_host, sizeof(uint16_t));

    memcpy(dns_msg->answer.rdata,
           recv_buf + 26 + qname_len + name_len, rdlength_host);

    return;
}

/**
 * get url from DNS message
 * @param qname     qname field
 * @param qname_len length
 * @param url       the url that is parsed
 */
void get_url(char *qname, size_t qname_len, char *url)
{
    memcpy(url, qname + 1, qname_len - 1);
    size_t i = qname[0];
    while (url[i] != 0)
    {
        uint8_t next_pos = url[i] + i + 1;
        url[i] = '.';
        i = next_pos;
    }

    return;
}


/**
 * Convert struct to text message to be send to proxy
 * @param  dns_msg     DNS message struct
 * @param  dns_msg_net text message
 * @param  if_correct  if it is a valid DNS query
 * @param  server_ip   server's IP that needs to response
 * @return             the length of dns_msg_net
 */
size_t form_response(dns_msg_t *dns_msg, char *dns_msg_net,
                     uint8_t if_correct, char *server_ip)
{
    size_t offset = 0;
    uint16_t id_host = dns_msg->id;
    uint16_t id_network = htons(id_host);
    memcpy(dns_msg_net + offset, &id_network, sizeof(uint16_t));
    offset += sizeof(uint16_t);

    dns_msg->qr = 1;
    dns_msg->aa = 1;
    dns_msg->tc = 0;
    dns_msg->rd = 0;
    dns_msg->ra = 0;
    dns_msg->z = 0;
    if (if_correct == 1)
    {
        dns_msg->rcode = 0;
    }
    else
    {
        dns_msg->rcode = 3;
    }

    memcpy(dns_msg_net + offset, (char *)dns_msg + 2, sizeof(uint16_t));
    offset += sizeof(uint16_t);

    uint16_t qdcount_host = 1;
    uint16_t qdcount_network = htons(qdcount_host);
    memcpy(dns_msg_net + offset, &qdcount_network, sizeof(uint16_t));
    offset += sizeof(uint16_t);

    uint16_t ancount_host;
    if (if_correct == 1)
    {
        ancount_host = 1;
    }
    else
    {
        ancount_host = 0;
    }
    uint16_t ancount_network = htons(ancount_host);
    memcpy(dns_msg_net + offset, &ancount_network, sizeof(uint16_t));
    offset += sizeof(uint16_t);

    uint16_t nscount_host = 0;
    uint16_t nscount_network = htons(nscount_host);
    memcpy(dns_msg_net + offset, &nscount_network, sizeof(uint16_t));
    offset += sizeof(uint16_t);

    uint16_t arcount_host = 0;
    uint16_t arcount_network = htons(arcount_host);
    memcpy(dns_msg_net + offset, &arcount_network, sizeof(uint16_t));
    offset += sizeof(uint16_t);

    memcpy(dns_msg_net + offset, dns_msg->question.qname,
           dns_msg->question.qname_len);
    offset += dns_msg->question.qname_len;

    uint16_t qtype_host = dns_msg->question.qtype;
    uint16_t qtype_network = htons(qtype_host);
    memcpy(dns_msg_net + offset, &qtype_network, sizeof(uint16_t));
    offset += sizeof(uint16_t);

    uint16_t qclass_host = dns_msg->question.qclass;
    uint16_t qclass_network = htons(qclass_host);
    memcpy(dns_msg_net + offset, &qclass_network, sizeof(uint16_t));
    offset += sizeof(uint16_t);

    if (if_correct == 0)
    {
        return offset;
    }

    memcpy(dns_msg_net + offset, dns_msg->question.qname,
           dns_msg->question.qname_len);
    offset += dns_msg->question.qname_len;

    uint16_t type_host = 1;
    uint16_t type_network = htons(type_host);
    memcpy(dns_msg_net + offset, &type_network, sizeof(uint16_t));
    offset += sizeof(uint16_t);

    uint16_t class_host = 1;
    uint16_t class_network = htons(class_host);
    memcpy(dns_msg_net + offset, &class_network, sizeof(uint16_t));
    offset += sizeof(uint16_t);

    uint32_t ttl_host = 0;
    uint32_t ttl_network = htonl(ttl_host);
    memcpy(dns_msg_net + offset, &ttl_network, sizeof(uint32_t));
    offset += sizeof(uint32_t);

    char ip_address_bin[4] = {0};
    str2bin(server_ip, ip_address_bin);
    uint16_t rdlength_host = 4;
    uint16_t rdlength_network = htons(rdlength_host);
    memcpy(dns_msg_net + offset, &rdlength_network, sizeof(uint16_t));
    offset += sizeof(uint16_t);

    memcpy(dns_msg_net + offset, ip_address_bin, 4);

    return offset + 4;
}

/**
 * IP's string converts to binary
 * @param server_ip      server IP that needs to be converted
 * @param ip_address_bin return value
 */
void str2bin(char *server_ip, char *ip_address_bin)
{
    int num1 = 0;
    int num2 = 0;
    int num3 = 0;
    int num4 = 0;

    sscanf(server_ip, "%d.%d.%d.%d", &num1, &num2, &num3, &num4);

    ip_address_bin[0] = (uint8_t)num1;
    ip_address_bin[1] = (uint8_t)num2;
    ip_address_bin[2] = (uint8_t)num3;
    ip_address_bin[3] = (uint8_t)num4;
}

void print_dns_msg(dns_msg_t *dns_msg)
{
    printf("-------print_dns_msg begins------\n");
    printf("ID: %d\n", dns_msg->id);
    printf("QR: %x\n", dns_msg->qr);
    printf("OPCODE: %x\n", dns_msg->opcode);
    printf("AA: %x\n", dns_msg->aa);
    printf("TC: %x\n", dns_msg->tc);
    printf("RD: %x\n", dns_msg->rd);
    printf("RA: %x\n", dns_msg->ra);
    printf("Z: %x\n", dns_msg->z);
    printf("RCODE: %x\n", dns_msg->rcode);
    printf("QDCOUNT: %d\n", dns_msg->qdcount);
    printf("ANCOUNT: %d\n", dns_msg->ancount);
    printf("NSCOUNT: %d\n", dns_msg->nscount);
    printf("ARCOUNT: %d\n", dns_msg->arcount);
    {
        size_t i = 0;
        size_t qname_len = dns_msg->question.qname_len;
        printf("QNAME: ");
        for (i = 0; i < qname_len; i++)
        {
            if (dns_msg->question.qname[i] < 64)
            {
                printf("%x", dns_msg->question.qname[i]);
            }
            else
            {
                printf("%c", dns_msg->question.qname[i]);
            }
        }
        printf("\n");
        printf("QNAME LEN: %d\n", dns_msg->question.qname_len);
        printf("QTYPE: %d\n", dns_msg->question.qtype);
        printf("QCLASS: %d\n", dns_msg->question.qclass);
    }
    if (dns_msg->qr == 1)
    {
        size_t i = 0;
        size_t name_len = dns_msg->answer.name_len;
        printf("NAME: ");
        for (i = 0; i < name_len; i++)
        {
            if (dns_msg->answer.name[i] < 64)
            {
                printf("%x", dns_msg->answer.name[i]);
            }
            else
            {
                printf("%c", dns_msg->answer.name[i]);
            }
        }
        printf("\n");
        printf("NAME_LEN: %d\n", dns_msg->answer.name_len);
        printf("TYPE: %d\n", dns_msg->answer.type);
        printf("CLASS: %d\n", dns_msg->answer.class_t);
        printf("TTL: %d\n", dns_msg->answer.ttl);
        printf("RDLENGTH: %d\n", dns_msg->answer.rdlength);
        printf("RDATA[0]: %d\n", *(char *)dns_msg->answer.rdata);
        printf("RDATA[1]: %d\n", *(char *)(dns_msg->answer.rdata + 1));
        printf("RDATA[2]: %d\n", *(char *)(dns_msg->answer.rdata + 2));
        printf("RDATA[3]: %d\n", *(char *)(dns_msg->answer.rdata + 3));

        // printf("RDATA[0]: %02hhx\n", *(char *)dns_msg->answer.rdata);
        // printf("RDATA[1]: %02hhx\n", *(char *)(dns_msg->answer.rdata + 1));
        // printf("RDATA[2]: %02hhx\n", *(char *)(dns_msg->answer.rdata + 2));
        // printf("RDATA[3]: %02hhx\n", *(char *)(dns_msg->answer.rdata + 3));
    }
    printf("-------print_dns_msg ends------\n");

    return;
}