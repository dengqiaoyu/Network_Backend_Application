#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <errno.h>
#include "proxy.h"
#include "comm_with_server.h"
#include "dbg.h"
#include "throughput.h"
#include "parse_manifest.h"

#define REQ_LINE 8192

extern FILE *logfp;
extern param proxy_param;
extern time_t proxy_start_time;

int8_t set_conn(pools_t *p, int connfd, char *fake_ip, char *www_ip,
                char *hostname, char *port)
{
    int8_t ret = 0;
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in localaddr;
    localaddr.sin_family = AF_INET;
    localaddr.sin_addr.s_addr = inet_addr(fake_ip);
    localaddr.sin_port = 0;
    ret = bind(sockfd, (struct sockaddr *)&localaddr, sizeof(localaddr));
    dbg_cp3_d2_printf("******** line 27 ******\n");
    if (ret == -1)
    {
        int errsv = errno;
        fprintf(logfp, "%s", strerror(errsv));
        dbg_cp3_d2_printf("--- line 31:%s \n----", strerror(errsv));
        return -1;
    }
    dbg_cp3_d2_printf("******** line 35 ******\n");
    struct sockaddr_in remoteaddr;
    remoteaddr.sin_family = AF_INET;
    dbg_cp3_d2_printf("******** line 39, check ip: %s ******\n", www_ip);
    remoteaddr.sin_addr.s_addr = inet_addr(www_ip);
    remoteaddr.sin_port = htons(8080);
    ret = connect(sockfd, (struct sockaddr *)&remoteaddr, sizeof(remoteaddr));
    if (ret == -1)
    {
        int errsv = errno;
        fprintf(logfp, "%s", strerror(errsv));
        dbg_cp3_d2_printf("--- line 44:%s \n----", strerror(errsv));
        return -1;
    }
    dbg_cp3_d2_printf("******** line 48 ******\n");
    fcntl(sockfd, F_SETFL, O_NONBLOCK);
    FD_SET(sockfd, &p->active_wt_set);
    p->serverfd[sockfd] = 1;
    p->fd_c2s[connfd] = sockfd;
    p->fd_s2c[sockfd] = connfd;
    p->send2s_list[connfd]->next = NULL;
    p->s2c_list[connfd]->next = NULL;
    // strncpy(p->log_rec_list[connfd]->server_ip,www_ip,15);
    strncpy(proxy_param.www_ip,www_ip,15);
    dbg_cp3_d2_printf("=== line 59, record ip: %s ====\n",
        p->log_rec_list[connfd]->server_ip);
    dbg_cp3_d2_printf("---- set_conn End -----\n\n");
    return 0;
}

send2s_req_t *form_request2s(Requests *req_rover, pools_t *pool, \
    manifest_t *mani,throughput_t * thr_info, int clientfd)
{
    int8_t ret = 0;
    send2s_req_t *send2s_req = malloc(sizeof(send2s_req_t));
    memset(send2s_req, 0, sizeof(send2s_req_t));
    uint8_t req_type = check_req_type(req_rover->http_uri);
    dbg_cp3_d2_printf("!!!! origin uir: %s\n", req_rover->http_uri);
    if(req_type == 2)
    {
        dbg_cp3_p3_printf("chunk download request from client\n");
        char *p = strstr(req_rover->http_uri, "Seg");
        char *p1 = p;
        char new_http_uri[MAX_SIZE + 1] = {0};
        char temp1[10] = {0};// store "/1000"before"Seg"
        dbg_cp3_d2_printf("#### before get new_bitrate ####\n");
        dbg_cp3_d2_printf("thr_cur check: %.6f\n",pool->thr_info->thr_cur[clientfd]);
        int new_bitrate = get_new_bitrate(pool,clientfd);
        pool->log_rec_list[clientfd]->req_bitrate = new_bitrate;

        int serverfd = pool->fd_s2c[clientfd];
        strncpy(pool->log_rec_list[clientfd]->server_ip, proxy_param.www_ip,15);
        dbg_cp3_d2_printf("### new_bitrate: %d\n###",new_bitrate);
        char bitrate_str[20] = {0};
        sprintf(bitrate_str,"%d",new_bitrate);
        dbg_cp3_d2_printf("### new_bitrate_str: %s\n###",bitrate_str);
        while(1)
        {
            p--;
            if(p[0] == '/')
            {
                p++;
                break;
            }
        }
        int i = 0;
        while(p!=p1)
        {
            temp1[i] = p[0];
            p++;
            i++;

        }
        uint16_t len = 
            strlen(req_rover->http_uri) - strlen(strstr(req_rover->http_uri, temp1));
        //copy from begin to before "/1000Seg"
        strncpy(new_http_uri, req_rover->http_uri, len);
        strncat(new_http_uri, bitrate_str, strlen(bitrate_str));
        strncat(new_http_uri,p1,strlen(p1));

        
        //need to add '\0' to end??
        strncpy(req_rover->http_uri, new_http_uri, MAX_SIZE);
        dbg_cp3_d2_printf("new chunk uri: %s\n", req_rover->http_uri);
        strncpy(pool->log_rec_list[clientfd]->chunk_name, req_rover->http_uri,39);
        dbg_cp3_d2_printf("line 111, new chunk uri: %s\n", pool->log_rec_list[clientfd]->chunk_name);
        /*********** record timestamp ts  *************/
        struct  timeval start;
        gettimeofday(&start,NULL);
        thr_info->ts_rec[clientfd].tv_sec = start.tv_sec;
        thr_info->ts_rec[clientfd].tv_usec = start.tv_usec;
        thr_info->send_fra_req[clientfd] = 1;
        //ready to send request for video fragment

    }
    ret = assemble_req(send2s_req, req_rover);
    if (ret < 0)
    {
        dbg_cp3_p3_printf("line 96\n");
        return NULL;
    }
    if (req_type == 1)
    {
        dbg_cp3_p3_printf(".f4m request from client\n");
        send2s_req->next = malloc(sizeof(send2s_req_t));
        memset(send2s_req->next, 0, sizeof(send2s_req_t));
        uint16_t len =
            strlen(req_rover->http_uri) - strlen(strstr(req_rover->http_uri, ".f4m"));
        char *p3 = strstr(req_rover->http_uri, ".f4m");
        char new_http_uri[MAX_SIZE + 1] = {0};
        strncpy(new_http_uri, req_rover->http_uri, len);
        strncat(new_http_uri, "_nolist.f4m\0", 11);
        strncpy(req_rover->http_uri, new_http_uri, MAX_SIZE);
        dbg_cp3_d2_printf("new uri: %s\n", req_rover->http_uri);
        
        ret = assemble_req(send2s_req->next, req_rover);
        dbg_cp3_d2_printf("------- check request -----\n");
        print_request2s(send2s_req->next);
        dbg_cp3_d2_printf("------- end check request -----\n\n");
        if (ret < 0)
        {
            return NULL;
        }
        else
        {
            mani->flag_send_f4m[clientfd] = 1;//creat f4m,wait to send
            //dbg_cp3_d2_printf("-##--flag_f4m:%d--##-\n",mani->flag_send_f4m[clientfd]);
            mani->f4m_req[clientfd] = send2s_req;
        }
    }
    return send2s_req;
}

int8_t assemble_req(send2s_req_t *send2s_req, Requests *req_rover)
{
    char *request = send2s_req->request;
    char line[REQ_LINE + 1] = {0};
    uint16_t req_capacility = REQ_BUF_SIZE;
    dbg_cp3_d2_printf("---- line 167, req_rover->http_method: %s \n", 
        req_rover->http_method);
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
            dbg_cp3_p3_printf("req_capacility: %d\n",
                              req_capacility);
            dbg_cp3_p3_printf("req_rover->entity_len: %d\n",
                              req_rover->entity_len);
            return -1;
        }
        memcpy(request + send2s_req->len, req_rover->entity_body,
               req_rover->entity_len);
    }
    send2s_req->next = NULL;
    send2s_req->len += req_rover->entity_len;
    send2s_req->offset = 0;

    return 0;
}

int8_t req_send2s(int connfd, pools_t *p)
{
    send2s_req_t *send2s_req_start = p->send2s_list[connfd];
    send2s_req_t *rover = send2s_req_start->next;
    int serverfd = p->fd_c2s[connfd];
    ssize_t write_ret = 0;
    int8_t ret = 0;
    size_t iter_cnt = 0;
    dbg_cp3_d2_printf("serverfd: %d\n", serverfd);
    dbg_cp3_d2_printf("------sending list in req_send2s-------\n");
    print_request2s(rover);
    dbg_cp3_d2_printf("------sending list in req_send2s-------\n");
    time_t time_now = time(NULL);
    time_t time_diff = difftime(time_now,proxy_start_time);
    int minute = time_diff/60;
    dbg_cp3_d2_printf("\n======  time since start: %ld sec =====\n\n", time_diff);
     dbg_cp3_d2_printf("\n======  time since start: %d min, %ld sec =====\n\n", minute,time_diff%60);
    


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
                /************ Add New Code *************/
                if(p->mani_info->flag_send_f4m[connfd] == 1)
                {
                    send2s_req_t *f4m_req = p->mani_info->f4m_req[connfd];
                    if(f4m_req == NULL)
                    {
                        printf("record of f4m_req pointer error\n");
                    }
                    else if(f4m_req == rover)
                    {
                        dbg_cp3_d2_printf("f4m_req is sent!\n");
                        p->mani_info->flag_send_f4m[connfd] = 2;
                        dbg_cp3_d2_printf("## clientfd ##: %d\n",connfd);
                        //f4m request is send
                        p->mani_info->f4m_req[connfd] == NULL;
                        free(rover);
                        break;
                    }
                }
                /****************** END *********************/
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
                printf("line 261, Failed sending request to server, disconnected.\n");
                Close_conn(connfd, p);
                Close_conn(serverfd, p);
                printf("line 264, end of print\n");
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
    char *p = NULL;
    if (sub_string != NULL && strlen(sub_string) == 4)
    {
        return 1;
    }
    else if((p = strstr(http_uri, "Seg"))!= NULL)
    {
        return 2;
    }
    else
    {
        return 0;
    }
}
