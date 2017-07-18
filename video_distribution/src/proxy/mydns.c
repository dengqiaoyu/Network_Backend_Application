/******************************************************************************
 *                                 Video CDN                                  *
 *                          15-641 Computer Network                           *
 *                                  mydns.c                                   *
 * This file contains the implementation of all the functions used by proxy in*
 * dns query, including set up dns connection, build dns msg, send and receive*
 * dns msg.                                                                   *
 * Author: Qiaoyu Deng; Yangmei Lin                                           *
 * Andrew ID: qdeng; yangmeil                                                 *
 ******************************************************************************/
#include "mydns.h"
#include "comm_with_server.h"
#include "server_to_client.h"
extern param proxy_param;

/**
 * proxy sets up connection with dns server
 * @return 0 for success, -1 for error
 */
int conn_dns_server(int port, dns_t * dns_info, pools_t *p) //port is 0
{
    int sock;
    struct sockaddr_in myaddr;


    FD_ZERO(&(dns_info->read_set));
    FD_ZERO(&(dns_info->write_set));

    if ((sock = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_IP)) == -1)
    {
        perror("DNS library could not create socket");
        exit(-1);
    }

    bzero(&myaddr, sizeof(myaddr));
    myaddr.sin_family = AF_INET;
    myaddr.sin_addr.s_addr = inet_addr(proxy_param.fake_ip);;
    myaddr.sin_port = htons(port);

    if (bind(sock, (struct sockaddr *) &myaddr, sizeof(myaddr)) == -1)
    {
        perror("DNS library could not bind socket");
        exit(-1);
    }

    FD_SET(sock, &dns_info->read_set);
    FD_SET(sock, &dns_info->write_set);
    FD_SET(sock, &p->active_rd_set);
    dns_info->dns_sock = sock;

    return 0;
}

/**
 * initialize dns request message
 * @return NULL
 */
void init_dns_msg_req(dns_msg_t *dns_msg)
{
    dns_msg->qr = 0;
    dns_msg->opcode = 0;
    dns_msg->aa = 0;
    dns_msg->tc = 0;
    dns_msg->rd = 0;
    dns_msg->ra = 0;
    dns_msg->z = 0;
    dns_msg->rcode = 0;
    dns_msg->qdcount = 1;
    dns_msg->ancount = 0;
    dns_msg->nscount = 0;
    dns_msg->arcount = 0;
    dns_msg->question.qtype = 1;
    dns_msg->question.qclass = 1;
}

/**
 * form a dns query message and add the message struct into dns msg list
 * @return the updated dns msg list list
 */
dns_msg_list_t* form_dns_query(char *servername, dns_t * dns_info, int clientfd)
{
    dns_msg_t * dns_request = malloc(sizeof(dns_msg_t));
    dns_msg_list_t *dns_req_list = malloc(sizeof(dns_msg_list_t));
    init_dns_msg_req(dns_request);
    dns_request->id = dns_info->cur_id + 1;
    dns_info->cur_id += 1;
    strncpy(dns_request->question.qname, servername, strlen(servername));
    dns_request->question.qname_len = strlen(servername) + 1;
    dns_req_list->dns_msg = dns_request;
    dns_req_list->next = NULL;
    dns_info->dnsid_client[dns_info->cur_id] = clientfd;
    return dns_req_list;
}

/**
 * form a dns query message string based on dns_msg_t struct for UDP sendto()
 * @return the length of dns query message string
 */
int form_dns_req_str(char * msg_str, dns_msg_t* msg_t)
{
    int offset = 0;
    memcpy(msg_str, msg_t + offset, 2);
    offset += 2;
    memcpy(msg_str + offset, msg_t + offset, 2);
    offset += 2;
    memcpy(msg_str + offset, &msg_t->qdcount, 2);
    offset += 2;
    memcpy(msg_str + offset, &msg_t->ancount, 2);
    offset += 2;
    memcpy(msg_str + offset, &msg_t->nscount, 2);
    offset += 2;
    memcpy(msg_str + offset, &msg_t->arcount, 2);
    offset += 2;
    memcpy(msg_str + offset, &msg_t->question.qname, msg_t->question.qname_len);
    offset += msg_t->question.qname_len;
    memcpy(msg_str + offset, &msg_t->question.qtype, 2);
    offset += 2;
    memcpy(msg_str + offset, &msg_t->question.qclass, 2);
    offset += 2;
    return offset;//msg_str len

}

/**
 * help function that print string in form of hexadecimal number
 * @return NULL
 */
void print_hex_str(char * msg_str, int len)
{
    int i = 0;
    printf("-------- dns message ----------\n");
    for (i = 0; i < len; i++)
    {
        printf("%02hhx", msg_str[i]);
    }
    printf("\n");
    printf("--------------------------------\n");

}

/**
 * find the last element of dns msg list
 * @return the pionter of the last element
 */
dns_msg_list_t* find_last_dns_req(dns_msg_list_t* dns_msg_list_h)
{
    dns_msg_list_t* rover = dns_msg_list_h;
    while (rover->next != NULL)
    {
        rover = rover->next;
    }
    return rover;
}

/**
 * get Host header value from Get request
 * @return NULL
 */
void get_hostname(Requests *reqs, char *hostname)
{
    Requests *req_rover = reqs;
    Request_header *header_rover = req_rover->headers;

    int i = 0;
    for (i = 0; i < req_rover->h_count; i++)
    {
        if (strcmp(header_rover[i].h_name, "Host") == 0)
        {
            strcpy(hostname, header_rover[i].h_value);
            break;
        }
    }
}

/**
 * form a qname string of dns query message based on origin hostname string
 * @return the pionter of qname string
 */
char * form_qname(char *hostname)
{
    int i = 0, j = 0;
    int dot_num = 1;
    int word_len[10] = {0};
    int word_c = 0;
    int word_num = 0;
    for (i; i < strlen(hostname); i++)
    {
        if (hostname[i] == '.')
        {
            dot_num += 1;
            word_len[j] = word_c;
            j++;
            word_c = 0;
        }
        else if (hostname[i] == ':')
        {
            break;
        }
        else
        {
            word_c += 1;
        }
    }
    word_len[j] = word_c;
    word_num = j;
    j = 1;
    char *qname = malloc((strlen(hostname) + 2) * sizeof(char));
    memset(qname, 0, strlen(hostname) + 2);
    qname[0] = word_len[0];

    for (i = 0; i < strlen(hostname); i++)
    {
        if (hostname[i] == '.')
        {
            qname[i + 1] = word_len[j];
            j++;
        }
        else if (hostname[i] == ':')
        {
            break;
        }
        else
        {
            qname[i + 1] = hostname[i];
        }
    }
    qname[i + 1] = '\0';

    return qname;

}

/**
 * Connect server for client based on dns response message
 * another side.
 * @return 0 for success
 */
int conn_cli_server(dns_msg_t * dns_response, pools_t *p)
{
    char ip_addr[20] = {0};
    bin2str(dns_response->answer.rdata, ip_addr);
    uint16_t id = dns_response->id;
    int i = p->dns_info->cur_id;
    int clientfd;
    char hostname[1024] = {0};
    char port[1024] = {0};
    clientfd = p->dns_info->dnsid_client[id];
    set_conn(p, clientfd, proxy_param.fake_ip, ip_addr,
             hostname, port);
    p->dns_info->client_stat[clientfd] = 3;
    send_first_req(p, clientfd);

    return 0;

}

/**
 * transfer binary ip address to string ip address
 * @return NULL
 */
void bin2str(char *rdata, char *ip_addr)
{
    sprintf(ip_addr, "%d.%d.%d.%d", (char)rdata[0], (char)rdata[1], (char)rdata[2],
            (char)rdata[3]);
}

/**
 * send the first request of a client to server after building conncection
 * @return NULL
 */
void send_first_req(pools_t *p, int clientfd)
{
    Requests *reqs = p->client_reqs[clientfd];
    Requests *req_rover = reqs;
    while (req_rover != NULL)
    {
        if (strcmp(req_rover->http_method, "GET") != 0)
        {
            continue;
        }
        send2s_req_t *request2s = form_request2s(req_rover, p, p->mani_info, \
                                  p->thr_info, clientfd);
        if (request2s == NULL)
        {
            Close_conn(clientfd, p);
        }
        send2s_req_t *last_send2s_req =
            find_last_send2s_req(p->send2s_list[clientfd]);
        last_send2s_req->next = request2s;
        req_rover = req_rover->next_req;
    }
    destory_requests(reqs);
    reqs = NULL;
    p->client_reqs[clientfd] = NULL;
    req_send2s(clientfd, p);
}

/**
 * This function convert a host-byte-order packet to a network-byte-order packet.
 * @return  Never returns.
 */
void packet2net(dns_msg_t * dns_msg)
{
    dns_msg->id =
        htons(dns_msg->id);
    dns_msg->qdcount =
        htons(dns_msg->qdcount);
    dns_msg->ancount =
        htons(dns_msg->ancount);
    dns_msg->nscount =
        htons(dns_msg->nscount);
    dns_msg->arcount =
        htons(dns_msg->arcount);
    dns_msg->question.qtype =
        htons(dns_msg->question.qtype);
    dns_msg->question.qclass =
        htons(dns_msg->question.qclass);
}

/**
 * This function convert a network-byte-order packet to a host-byte-order packet.
 * @return  Never returns.
 */
void packet2host(dns_msg_t * dns_msg)
{
    dns_msg->id = ntohs(dns_msg->id);
    dns_msg->qdcount = ntohs(dns_msg->qdcount);
    dns_msg->ancount = ntohs(dns_msg->ancount);
    dns_msg->nscount = ntohs(dns_msg->nscount);
    dns_msg->arcount = ntohs(dns_msg->arcount);
    dns_msg->answer.type =
        ntohs(dns_msg->answer.type);
    dns_msg->answer.class_t =
        ntohs(dns_msg->answer.class_t);
    dns_msg->answer.ttl =
        ntohs(dns_msg->answer.ttl);
    dns_msg->answer.rdlength =
        ntohs(dns_msg->answer.rdlength);
}

/**
 * This function handles dns msg receiving and sending with dns server
 * @return  0 if success, -1 if error
 */
int dns_process(dns_t * dns_info, pools_t *p)
{
    int nfds;
    int sock = dns_info->dns_sock;
    fd_set readfds = dns_info->read_set;
    fd_set writefds = dns_info->write_set;
    ssize_t writeret = 0;
    ssize_t readret = 0;

    struct sockaddr_in addr;
    bzero(&addr, sizeof(addr));
    inet_pton(AF_INET, proxy_param.dns_ip, &(addr.sin_addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((unsigned short)atoi(proxy_param.dns_port));

    struct sockaddr_in from;
    socklen_t fromlen;
    char buf[UDP_RECV_BUFLEN + 1] = {0};


    nfds = select(sock + 1, &readfds, &writefds, NULL, NULL);
    if (nfds > 0)
    {
        if (FD_ISSET(sock, &readfds))//receiving packets
        {
            while (1)
            {
                readret = recvfrom(sock, buf, UDP_RECV_BUFLEN, 0,
                                   (struct sockaddr *) &from, &fromlen);
                if (readret == -1)
                {
                    if (errno == EAGAIN || errno == EWOULDBLOCK)
                    {
                        break;
                    }
                    else
                    {
                        printf("Something wrong with UDP socket\n");
                        exit(1);
                    }
                }
                else
                {
                    dns_msg_t dns_response;
                    parse_dns_msg(&dns_response, buf, readret);
                    conn_cli_server(&dns_response, p);
                }
            }

        }
        if (FD_ISSET(sock, &writefds))//sending packets
        {
            dns_msg_list_t* rover = dns_info->dns_msg_list->next;
            dns_msg_list_t* rover_last = dns_info->dns_msg_list;
            while (rover != NULL)
            {
                dns_msg_t msg2convert;
                memset(&msg2convert, 0, sizeof(dns_msg_t));
                memcpy(&msg2convert, rover->dns_msg, DNS_REQ_LEN);
                packet2net(&msg2convert);
                char msg_str[DNS_SEND_BUFLEN] = {0};
                int msg_len = form_dns_req_str(msg_str, &msg2convert);
                writeret = sendto(sock, msg_str, msg_len, 0,
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
                        return -1;
                    }
                }
                else
                {
                    rover_last->next = rover->next;
                    free(rover->dns_msg);
                    free(rover);
                    rover = rover_last->next;
                }
            }

        }
    }
    return 0;

}

/**
 * parse recieved dns msg string to dns_msg_t struct
 * @return NULL
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
 * print dns msg using dns_msg_t struct
 * @return NULL
 */
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
    }
    printf("-------print_dns_msg ends------\n");

    return;
}