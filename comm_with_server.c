#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <errno.h>
#include "proxy.h"
#include "comm_with_server.h"
#include "dbg.h"

#define REQ_LINE 1024

extern FILE *logfp;

int8_t set_conn(pools_t *p, int connfd, char *fake_ip, char *www_ip,
                char *hostname, char *port)
{
    int8_t ret = 0;
    // int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    // struct sockaddr_in localaddr;
    // localaddr.sin_family = AF_INET;
    // localaddr.sin_addr.s_addr = inet_addr(fake_ip);
    // localaddr.sin_port = 0;
    // ret = bind(sockfd, (struct sockaddr *)&localaddr, sizeof(localaddr));
    // if (ret == -1)
    // {
    //     int errsv = errno;
    //     fprintf(logfp, "%s", strerror(errsv));
    //     return -1;
    // }

    // struct sockaddr_in remoteaddr;
    // remoteaddr.sin_family = AF_INET;
    // remoteaddr.sin_addr.s_addr = inet_addr(www_ip);
    // remoteaddr.sin_port = htons(8080);
    // ret = connect(sockfd, (struct sockaddr *)&remoteaddr, sizeof(remoteaddr));
    // if (ret == -1)
    // {
    //     int errsv = errno;
    //     fprintf(logfp, "%s", strerror(errsv));
    //     return -1;
    // }
    //
    int sockfd;
    {
        struct addrinfo hints, *listp, *p;

        /* Get a list of potential server addresses */
        memset(&hints, 0, sizeof(struct addrinfo));
        hints.ai_socktype = SOCK_STREAM;  /* Open a connection */
        hints.ai_flags = AI_NUMERICSERV;  /* ... using a numeric port arg. */
        hints.ai_flags |= AI_ADDRCONFIG;  /* Recommended for connections */
        int re = getaddrinfo(hostname, port, &hints, &listp);
        if (re != 0)
            return -1;

        /* Walk the list for one that we can successfully connect to */
        for (p = listp; p; p = p->ai_next) {
            /* Create a socket descriptor */
            if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) < 0)
                continue; /* Socket failed, try the next */

            /* Connect to the server */
            if (connect(sockfd, p->ai_addr, p->ai_addrlen) != -1)
                break; /* Success */
            Close(sockfd); /* Connect failed, try another */  //line:netp:openclientfd:closefd
        }

        /* Clean up */
        freeaddrinfo(listp);
        if (!p) /* All connects failed */
            return -1;
    }
    fcntl(sockfd, F_SETFL, O_NONBLOCK);
    FD_SET(sockfd, &p->active_wt_set);
    FD_SET(sockfd, &p->active_rd_set);
    p->serverfd[sockfd] = 1;
    p->fd_c2s[connfd] = sockfd;
    p->fd_s2c[sockfd] = connfd;
    p->send2s_list[connfd]->next = NULL;
    p->s2c_list[connfd]->next = NULL;
    return 0;
}

send2s_req_t *form_request2s(Requests *req_rover)
{
    int8_t ret = 0;
    send2s_req_t *send2s_req = malloc(sizeof(send2s_req_t));
    memset(send2s_req, 0, sizeof(send2s_req_t));
    uint8_t req_type = check_req_type(req_rover->http_uri);
    ret = assemble_req(send2s_req, req_rover);
    if (ret < 0)
    {
        return NULL;
    }
    if (req_type == 1)
    {
        send2s_req->next = malloc(sizeof(send2s_req_t));
        uint16_t len =
            req_rover->http_uri - strstr(req_rover->http_uri, ".f4m");
        char new_http_uri[MAX_SIZE + 1] = {0};
        strncpy(new_http_uri, req_rover->http_uri, len);
        strncat(new_http_uri, "nolist.f4m\0", 11);
        strncpy(req_rover->http_uri, new_http_uri, MAX_SIZE);
        ret = assemble_req(send2s_req->next, req_rover);
        if (ret < 0)
        {
            return NULL;
        }
    }
    return send2s_req;
}

int8_t assemble_req(send2s_req_t *send2s_req, Requests *req_rover)
{
    char *request = send2s_req->request;
    char line[REQ_LINE + 1] = {0};
    uint16_t req_capacility = REQ_BUF_SIZE;
    snprintf(line, REQ_LINE, "%s %s %s\n", req_rover->http_method,
             req_rover->http_uri, req_rover->http_version);
    strncat(request, line, req_capacility);
    req_capacility -= strlen(line);
    Request_header *header_rover = req_rover->headers;
    size_t i = 0;
    for (i = 0; i < req_rover->h_count; i++)
    {
        memset(line, 0, REQ_LINE);
        snprintf(line, REQ_LINE, "%s: %s\n", header_rover[i].h_name,
                 header_rover[i].h_value);
        strncat(request, line, req_capacility);
        req_capacility -= strlen(line);
    }
    strncat(request, "\n", req_capacility);
    req_capacility -= 1;
    send2s_req->len = strlen(request);
    // dbg_cp3_p3_printf("line 134 in comm_with_server.c: \n%s\n", request);
    // exit(1);
    if (req_rover->entity_body != NULL)
    {
        if (req_capacility < req_rover->entity_len)
        {
            return -1;
        }
        memcpy(request + send2s_req->len, req_rover->entity_body,
               req_rover->entity_len);
    }
    send2s_req->next = NULL;
    send2s_req->len += req_rover->entity_len;
    send2s_req->offset = 0;
}

int8_t req_send2s(int connfd, pools_t *p)
{
    send2s_req_t *send2s_req_start = p->send2s_list[connfd];
    send2s_req_t *rover = send2s_req_start->next;
    int serverfd = p->fd_c2s[connfd];
    ssize_t write_ret = 0;
    int8_t ret = 0;
    size_t iter_cnt = 0;
    dbg_cp3_p3_printf("------sending list in req_send2s-------\n");
    print_request2s(rover);
    dbg_cp3_p3_printf("------sending list in req_send2s-------\n");
    // exit(1);
    while (rover != NULL && iter_cnt <= MAX_WRIT_ITER_COUNT)
    {
        iter_cnt++;
        write_ret = write(serverfd, rover->request + rover->offset,
                          rover->len - rover->offset);

        if (write_ret > 0)
        {
            if (write_ret == rover->len - rover->offset)
            {
                send2s_req_start->next = rover->next;
                free(rover);
                rover = send2s_req_start->next;
            }
            else
            {
                rover->offset += write_ret;
            }
            // exit(1);
        }
        else if (write_ret < 0)
        {
            if (errno == EWOULDBLOCK || errno == EAGAIN)
            {
                break;
            }
            else
            {
                fprintf(logfp,
                        "Failed sending request to server, disconnected.\n");
                Close_conn(connfd, p);
                Close_conn(serverfd, p);
                return -1;
            }
        }
        else if (write_ret == 0)
        {
            Close_conn(connfd, p);
            Close_conn(serverfd, p);
            return 0;
        }
    }

    if (rover == NULL)
    {
        FD_CLR(serverfd, &p->active_wt_set);
    }
    else
    {
        if (!FD_ISSET(serverfd, &p->active_wt_set))
        {
            FD_SET(serverfd, &p->active_wt_set);
        }
    }

    if (!FD_ISSET(serverfd, &p->active_rd_set))
    {
        FD_SET(serverfd, &p->active_rd_set);
    }

    return 0;
}

inline send2s_req_t *find_last_send2s_req(send2s_req_t *send2s_list_h)
{
    send2s_req_t *rover = send2s_list_h;
    while (rover->next != NULL)
    {
        rover = rover->next;
    }

    return rover;
}

inline uint8_t check_req_type(char *http_uri)
{
    char *sub_string = strstr(http_uri, ".f4m");
    if (sub_string != NULL && strlen(sub_string) == 4)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}