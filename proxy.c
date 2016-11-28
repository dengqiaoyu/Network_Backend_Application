#include "proxy.h"
#include "param_init.h"
#include "log.h"
#include "hlp_func.h"
#include "constants.h"
#include "comm_with_server.h"
#include "server_to_client.h"
#include "throughput.h"
#include "parse_manifest.h"

FILE *logfp = NULL;
FILE *log_pFile = NULL;
int logfd = -1;
int errfd = -1; // reserve for one fd
param proxy_param;
time_t proxy_start_time;

void get_host_and_port(Requests *req_rover, char *hostname, char *port);

/**
 * This is the main function of lisod, and it can listen, accept, add client
 * and serve the client.
 * @return      Never returns
 */
int main(int argc, char **argv)
{
    proxy_start_time = time(NULL);
    int listenfd, connfd;
    ssize_t ret;
    socklen_t client_len;
    struct sockaddr_storage client_addr;
    static pools_t pool;
    struct timeval tv_selt = {S_SELT_TIMEOUT, US_SELT_TIMEOUT};
    mode_t m_error = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;

    dbg_cp2_printf("----- Proxy -----\n");

    ret = get_argv(argc, argv, &proxy_param);
    if (ret < 0)
    {
        fprintf(stderr, "Argumens is not valid, proxy terminated.\n");
        return -1;
    }
    // print_argv(&proxy_param);

    // logfd = init_log(proxy_param.log, argc, argv);
    // To handle max connection, need reserve one more fd to send error message
    errfd = open("./fd_reserved", O_WRONLY | O_CREAT, m_error);
    // if (logfd < 0)
    // {
    //     fprintf(stderr, "Log file initialnizing failed, proxy terminated.\n");
    //     return -1;
    // }
    //logfp = fdopen(logfd, "a");
    log_pFile = fopen(proxy_param.log, "a");
    logfp = fopen("proxy_check.log","a");

    listenfd = open_listenfd(proxy_param.lisn_port);
    if (listenfd < 0)
    {
        fprintf(logfp, "Port listening failed, proxy terminated\n");
        fupdate(logfp);
        return -1;
    }

    init_pool(listenfd, &pool);
    dbg_cp3_d2_printf("!!! check thr_info: %.6f, %.6f\n", pool.thr_info->thr_cur[6],pool.thr_info->thr_cur[7]);

    while (1)
    {
        pool.ready_rd_set = pool.active_rd_set;
        pool.ready_wt_set = pool.active_wt_set;
        pool.num_ready = select(FD_SETSIZE, &pool.ready_rd_set,
                                &pool.ready_wt_set, NULL, NULL);

        int errsv = errno;
        //dbg_cp3_d2_printf("\n\n\n\n\n\n\nnum_ready: %d, errno: %d\n", pool.num_ready, errsv);
        // htttp port accept connection
        if (pool.num_ready < 0)
        {
            dbg_cp3_p3_printf("%s\n", strerror(errsv));
        }

        if (FD_ISSET(listenfd, &pool.ready_rd_set))
        {
            client_len = sizeof(struct sockaddr_storage);
            connfd = accept(listenfd, (struct sockaddr *)&client_addr,
                            &client_len);
            dbg_cp3_d2_printf("\n!!!!! accept new clientfd: %d\n",connfd);
            if (connfd < 0)
            {
                // handle max connection and send error message back
                if (errno == EMFILE || errno == ENFILE)
                {
                    Close(errfd);
                    errfd = accept(listenfd, (struct sockaddr *)&client_addr,
                                   &client_len);
                    ret = send_maxfderr(errfd);
                    Close(errfd);
                    errfd = open("./fd_reserved", O_WRONLY | O_CREAT,
                                 m_error);
                }
                else
                {
                    fprintf(logfp, "Failed accepting coonection in main\n");
                    fupdate(logfp);
                    continue;
                }
            }
            else
            {
                char c_host[MAXLINE], c_port[MAXLINE];
                int flags = NI_NUMERICHOST | NI_NUMERICSERV;
                ret = getnameinfo((struct sockaddr *)&client_addr, client_len,
                                  c_host, MAXLINE, c_port, MAXLINE, flags);
                if (ret != 0)
                {
                    fprintf(logfp, "Can not resolve client's IP ");
                    fprintf(logfp, "or port in main.\n");
                    fupdate(logfp);
                }
                else
                {
                    fprintf(logfp, "Accept connection from client %s:%s.\n",
                            c_host, c_port);
                    fupdate(logfp);
                }
                // Add client to the read-write pools_t
                ret = add_client(connfd, &pool, c_host);
                dbg_cp3_p3_printf("c_host: %s, c_port: %s\n", c_host, c_port);
                if (ret < 0)
                {
                    Close(connfd);
                    fprintf(logfp, "Client adding failed in main.\n");
                    fupdate(logfp);
                }
            }
        }
        // Serve all of client within the pools_t
       	dbg_cp3_p3_printf("\n\nbefore line 124\n");
        ret = serve_clients(&pool);
        if (ret < 0)
        {
            fprintf(logfp, "serve_clients Failed.\n");
            fupdate(logfp);
        }
        fupdate(logfp);
    }

    ret = fclose(logfp);
    if (ret != 0)
    {
        fprintf(logfp, "Failed close file pointer.\n");
        fupdate(logfp);
        exit(1);
    }
    return 0;
}



/**
 * Open, bind and listen http port
 * @param  port http port
 * @return      -1 for fail, fd for success
 */
int open_listenfd(char *port)
{
    struct addrinfo hints, *listp, *p;
    int listenfd, optval = 1;
    ssize_t ret;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE | AI_ADDRCONFIG;
    hints.ai_flags |= AI_NUMERICSERV;

    ret = getaddrinfo(NULL, port, &hints, &listp);
    if (ret != 0) {
        fprintf(logfp, "Failed getting address information in open_listefd.\n");
        fupdate(logfp);
        return -1;
    }

    for (p = listp; p != NULL; p = p->ai_next) {
        listenfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (listenfd < 0) {
            continue;
        }

        if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR,
                       (const void *)&optval, sizeof(int)) < 0) {
            continue;
        }
        if (bind(listenfd, p->ai_addr, p->ai_addrlen) == 0) {
            break;
        }
        else {
            if (close(listenfd) < 0)
            {
                fprintf(logfp, "Failed closing listening file descriptor in");
                fprintf(logfp, "open_listenfd.\n");
                fupdate(logfp);
                return -1;
            }
        }
    }

    freeaddrinfo(listp);
    if (!p) {
        fprintf(logfp, "No address worked in open_listenfd.\n");
        fupdate(logfp);
        return -1;
    }

    ret = listen(listenfd, LISTENQ);
    if (ret < 0) {
        ret = close(listenfd);
        if (ret < 0) {
            fprintf(logfp, "Failed closing listening file descriptor ");
            fprintf(logfp, "in open_listenfd.\n");
            fupdate(logfp);
            return -1;
        }
        fprintf(logfp, "Failed listening on socket.\n");
        fupdate(logfp);
        return -1;
    }

    return listenfd;
}

/**
 * Select client that is ready for read or write to complete request
 * @param  p pool
 * @return   0 for success
 */
ssize_t serve_clients(pools_t *p)
{
    size_t i;
    ssize_t read_ret, ret;
    char skt_read_buf[SKT_READ_BUF_SIZE + 1] = {0};

    dbg_cp3_p3_printf("num_ready: %d\n", p->num_ready);
    // Magic number 7 indicates avaliable file descriptor starts from 7.
    for (i = 6; (i < FD_SETSIZE) && (p->num_ready > 0); i++)
    {
        dbg_wselet_printf("connfd: %ld, status: %d\n", i, p->clientfd[i]);
        // Client ready for read
        if ((p->clientfd[i] == 1) && (FD_ISSET(i, &p->ready_rd_set)))
        {
            int clientfd = i;
            char if_conn_close = 0;
            size_t read_offset = 0;
            size_t iter_count = 0;
            p->num_ready--;
            read_ret = 0;
            memset(skt_read_buf, 0, SKT_READ_BUF_SIZE + 1);

            // Read as much as possible, but need iter_count to be unblock
            do
            {
                iter_count++;
                read_offset = read_offset + read_ret;
                if (read_offset == SKT_READ_BUF_SIZE)
                {
                    break;
                }
                read_ret = read(clientfd, &skt_read_buf[read_offset],
                                SKT_READ_BUF_SIZE - read_offset);
                //dbg_cp3_p3_printf("read_ret for skt_read_buf: %ld\n", read_ret);
                dbg_cp3_d2_printf("line 265,read_ret for skt_read_buf: %ld\n", read_ret);
                // Client closes connection
                if (read_ret == 0)
                {
                    Close_conn(clientfd, p);
                    if_conn_close = 1;
                    break;
                }
                else if (read_ret < 0)
                {
                    if (read_offset == 0)
                    {
                        if_conn_close = 1;
                    }
                    // EWOULDBLOCK indicates no more data to be read
                    if (errno != EAGAIN && errno != EWOULDBLOCK) {
                        Close_conn(clientfd, p);
                        if_conn_close = 1;
                    }
                    break;
                }
            } while (iter_count < MAX_READ_ITER_COUNT);
            if (if_conn_close == 1)
            {
                continue;
            }
            //dbg_cp3_p3_printf("\nline 274 read_ret %ld: \n%s", read_ret,
                              //skt_read_buf);
            dbg_cp3_p3_printf("\nline 294 read_ret %ld: \n", read_ret);
            dbg_cp3_p3_printf("line 294: skt_read_buf start: %c%c%c%c\n", skt_read_buf[0],skt_read_buf[1],skt_read_buf[2],skt_read_buf[3]);
            fflush(stdout);
            // if(skt_read_buf[0] == 'P' && skt_read_buf[1] == 'O' && skt_read_buf[2] == 'S' && skt_read_buf[3] == 'T')
            // {
            //     memset(skt_read_buf,0,SKT_READ_BUF_SIZE + 1);
            //     continue;
            // }
            
            // Uses parse to get request's inofrmation
            Requests *reqs = parse(skt_read_buf, read_offset, clientfd, p);
            dbg_cp3_d2_printf("!!!parse success\n");
            Requests *req_rover = reqs;
            // For pipeline request, server them one by one
            char hostname[1024] = {0};
            char port[1024] = {0};

            //get_host_and_port(req_rover, hostname, port);
            dbg_cp3_d2_printf("line 312 after get_host_and_port\n");
            if (p->fd_c2s[clientfd] == -1)
            {
                //dbg_cp3_p3_printf("hostname: %s, port: %s\n", hostname, port);
                set_conn(p, clientfd, proxy_param.fake_ip, proxy_param.www_ip,
                         hostname, port);
                dbg_cp3_p3_printf("serverfd: %d\n", p->fd_c2s[clientfd]);
                // exit(1);
            }
            while (req_rover != NULL)
            {
                dbg_cp3_d2_printf("line 323 into while\n");
                if(strcmp(req_rover->http_method, "GET") != 0)
                {
                    dbg_cp3_d2_printf("!!! Not GET request !!!\n");
                    dbg_cp3_d2_printf("Method: %s\n",req_rover->http_method);
                    dbg_cp3_d2_printf("Uri: %s\n", req_rover->http_uri);
                    continue;
                }
                send2s_req_t *request2s = form_request2s(req_rover, p, p->mani_info,p->thr_info, clientfd);
                dbg_cp3_p3_printf("addr: %p\n", request2s);
                if (request2s == NULL)
                {
                    print_req(req_rover);
                    dbg_cp3_p3_printf("line 307\n");
                    Close_conn(clientfd, p);
                }
                // print_request2s(request2s);
                send2s_req_t *last_send2s_req =
                    find_last_send2s_req(p->send2s_list[clientfd]);
                last_send2s_req->next = request2s;
                req_rover = req_rover->next_req;
            }
            // dbg_cp3_d2_printf("line 338 before destroy\n");
            destory_requests(reqs);
            // dbg_cp3_d2_printf("line 340 after destroy\n");
            reqs = NULL;
            req_send2s(clientfd, p);
            // dbg_cp3_d2_printf("line 343 after req_send2s\n");
        }
        else if ((p->clientfd[i] == 1) && (FD_ISSET(i, &p->ready_wt_set)))
        {
            // In this case, client is ready to be send data
            
            dbg_cp3_d2_printf("line 361 client: %d\n", i);
            p->num_ready--;
            int clientfd = i;
            if (p->s2c_list[clientfd]->next == NULL)
            {
                continue;
            }
            // dbg_cp3_p3_printf("line 331\n");
            // dbg_cp3_p3_printf("line 332\n");
            dbg_cp3_d2_printf("line 370\n");
            ret = s2c_list_write_client(p, clientfd);

        }
        else if ((p->serverfd[i] == 1) && (FD_ISSET(i, &p->ready_rd_set)))
        {
            //dbg_cp3_d2_printf("line348,server is ready to read\n");
            int serverfd = i;
            int clientfd = p->fd_s2c[serverfd];
            dbg_cp3_p3_printf("server returns data\n");
            p->num_ready--;
            ret = s2c_list_read_server(p, serverfd);
            /*********  Add New Code      **********/
            //dbg_cp3_d2_printf("--##--clientfd:%d, flag_f4m:%d--##--\n",clientfd,p->mani_info->flag_send_f4m[i]);
            if(p->mani_info->flag_send_f4m[clientfd] == 2)//receive .f4m file
            {
                req_send2s(clientfd,p);
                dbg_cp3_p3_printf("receive .f4m file from server\n");
                char *mani_file = get_f4m_content(p, clientfd);
                if(mani_file == NULL)
                {
                    printf("error,mani_file is NULL!\n");
                }
                else
                {
                    FD_CLR(clientfd, &p->active_wt_set);
                    //assume parse result is right, wait to add error process later
                    p->mani_info->bitrate_rec[clientfd] = parse_manifest(mani_file);
                    p->mani_info->flag_send_f4m[clientfd] = 0;
                    p->thr_info->thr_cur[clientfd] = p->mani_info->bitrate_rec[clientfd]->bitrate[0];
                    dbg_cp3_d2_printf("-!!!!--- T current %d init by mani: %.6f -!!!---\n", clientfd, p->thr_info->thr_cur[clientfd]);

                    if(p->ip2mani_ht == NULL)
                    {
                        p->ip2mani_ht = ht_create(HASHTABLE_MINSIZE,\
                                       HASHTABLE_MAXSIZE, NULL);
                    }
                    char ip_str[16] = {0};
                    strncpy(ip_str,&(p->clientip[clientfd][0]),15);
                    bitrate_t *mani_p =  p->mani_info->bitrate_rec[clientfd];
                    ret = ht_set_copy(p->ip2mani_ht, ip_str, 15, mani_p, \
                        sizeof(int)*101, NULL, NULL);
                    if(ret == -1)
                    {
                        printf("line 406, set ip2mani_ht error!\n");
                    }

                    if(p->ip2thr_ht == NULL)
                    {
                        p->ip2thr_ht = ht_create(HASHTABLE_MINSIZE,\
                                       HASHTABLE_MAXSIZE, NULL);
                    }
                    double init_thr = p->mani_info->bitrate_rec[clientfd]->bitrate[0];
                    ret = ht_set_copy(p->ip2thr_ht, ip_str, 15, &init_thr, \
                        sizeof(double), NULL, NULL);
                    if(ret == -1)
                    {
                        printf("line 419, set ip2thr_ht error!\n");
                    }

                    continue;
                }
                
            }
            else if(p->thr_info->send_fra_req[clientfd] == 1)//receive video frag
            {
                dbg_cp3_d2_printf("\n-----####### receive video frag ######---\n");
                
                
                int frag_len = get_frag_size(p,clientfd);
                int packet_len = get_package_size(p,clientfd, frag_len);
                p->frag_len[clientfd] = frag_len;
                p->pack_len[clientfd] = packet_len;
                dbg_cp3_d2_printf("---- frag_size :%d ----\n",p->frag_len[clientfd]);
                if(frag_len == 0)
                {
                    dbg_cp3_d2_printf("frag_len is 0, error!\n");
                }
                else
                {
                    p->thr_info->send_fra_req[clientfd] = 0;

                }
                dbg_cp3_d2_printf("--####### END of receive video frag ######---\n");
                dbg_cp3_d2_printf("line 456, clientfd: %d\n", clientfd);
                if (!FD_ISSET(clientfd, &p->active_wt_set))
                {
                    printf("line 459\n");
                    //FD_SET(clientfd, &p->active_wt_set);
                }
            }
            /********   End ************/
            if(p->pack_len[clientfd] != 0)
            {
                p->pack_len[clientfd] = update_pack_recv_len(p, clientfd, p->pack_len[clientfd]);
                if(p->pack_len[clientfd] == 0)
                {
                    dbg_cp3_d2_printf("\n!!!!line 473, recv complete package!!!!\n");
                    p->log_rec_list[clientfd]->cur_time = time(NULL);
                    struct timeval tf;
                    gettimeofday(&tf,NULL);

                    update_thr_cur(p->frag_len[clientfd], tf, proxy_param.alpha, \
                        p->thr_info, clientfd, p);
                    // dbg_cp3_d2_printf("--!!!-- T current :%.6f ---!!!-\n", p->thr_info->thr_cur[clientfd]);
                    print_to_log(p->log_rec_list[clientfd]);
                    memset(p->log_rec_list[clientfd], 0, sizeof(log_record_t));
                }
            }
            dbg_cp3_p3_printf("line 342 ret: %ld\n", ret);
            if (ret < -1)
            {
                fprintf(logfp, "Error, close connection with server\n");
            }
            else
            {
                FD_SET(clientfd, &p->active_wt_set);
                // dbg_cp3_p3_printf("line 352\n");
                // dbg_cp3_p3_printf("line 352\n");
                dbg_cp3_d2_printf("line 476\n");
                s2c_list_write_client(p, clientfd);
            }
        }
        else if ((p->serverfd[i] == 1) && (FD_ISSET(i, &p->ready_wt_set)))
        {
            // server is ready to write
            // dbg_cp3_d2_printf("server is ready to write\n");
            p->num_ready--;
            int serverfd = i;
            if (p->send2s_list[serverfd]->next != NULL)
            {
                int clientfd = p->fd_s2c[serverfd];
                req_send2s(clientfd, p);
            }
        }
    }
    return 0;
}

/**
 * When complete one request, destroy it
 * @param reqs request
 */
void destory_requests(Requests *reqs)
{
    Requests *req_rover = reqs;
    while (req_rover != NULL)
    {
        Requests *next_req = req_rover->next_req;
        free(req_rover->entity_body);
        free(req_rover->headers);
        req_rover->headers = NULL;
        free(req_rover);
        req_rover = next_req;
    }
}

/**
 * Close connection or close CGI fd
 * @param  connfd fd of client
 * @param  p      pool
 * @return        0 for success
 */
ssize_t Close_conn(int connfd, pools_t *p) {
    Close(connfd);
    FD_CLR(connfd, &p->active_rd_set);
    FD_CLR(connfd, &p->active_wt_set);
    if (p->clientfd[connfd] == 1)
    {
        dbg_cp3_p3_printf("Closing client fd %d\n", connfd);
        p->fd_c2s[connfd] = -1;
        p->clientfd[connfd] = -1;
        p->ign_first[connfd] = 0;
        p->too_long[connfd] = 0;
        p->close_fin[connfd] = 0;
        memset(p->cached_buf[connfd], 0, REQ_BUF_SIZE + 1);
        free(p->cached_req[connfd]);
        p->cached_req[connfd] = NULL;
        memset(p->clientip[connfd], 0, 16);
        memset(p->serverip[connfd], 0, 16);
        {
            send2s_req_t *rover_last = p->send2s_list[connfd];
            send2s_req_t *rover = rover_last->next;
            while (rover != NULL)
            {
                rover_last->next = rover->next;
                free(rover);
                rover = rover_last->next;
            }
        }
        {
            s2c_data_list_t *rover_last = p->s2c_list[connfd];
            s2c_data_list_t *rover = rover_last->next;
            while (rover != NULL)
            {
                rover_last->next = rover->next;
                free(rover);
                rover = rover_last->next;
            }
        }
    }
    else if (p->serverfd[connfd] == 1)
    {
        dbg_cp3_p3_printf("Closing server fd %d\n", connfd);
        p->fd_s2c[connfd] = -1;
        p->serverfd[connfd] = -1;
    }
    return 0;
}

/**
 * Send error message
 * @param  connfd fd of client
 * @return        0 for success, -1 for failure
 */
ssize_t send_maxfderr(int connfd)
{
    ssize_t ret;
    size_t text_len = 0;
    char resp_htext[MAX_TEXT + 1] = {0};
    char text_tmp[MAX_TEXT + 1] = {0};

    snprintf(text_tmp, MAX_TEXT, "HTTP/1.1 503 Service Unavailable\r\n");
    strncat(resp_htext, text_tmp, MAX_TEXT - text_len);
    text_len +=  strlen(text_tmp);
    snprintf(text_tmp, MAX_TEXT, "Connection: close\r\n");
    strncat(resp_htext, text_tmp, MAX_TEXT - text_len);
    text_len +=  strlen(text_tmp);
    char *time_GMT = get_rfc1123_date();
    snprintf(text_tmp, MAX_TEXT, "Date: %s\r\n", time_GMT);
    free(time_GMT);
    strncat(resp_htext, text_tmp, MAX_TEXT - text_len);
    text_len +=  strlen(text_tmp);
    snprintf(text_tmp, MAX_TEXT, "Server: liso/1.0\r\n\r\n");
    strncat(resp_htext, text_tmp, MAX_TEXT - text_len);
    text_len +=  strlen(text_tmp);

    ret = write_to_socket(connfd, resp_htext, NULL, NULL, 0);
    if (ret < 0) {
        fprintf(logfp, "Failed sending reponse to fd%d\n", connfd);
        fupdate(logfp);
        return -1;
    }

    return 0;
}


/**
 * Function that is used to block write, never used again in normal situation,
 * except for max connection error
 */
ssize_t write_to_socket(int connfd, char *resp_hds_text, char *resp_ct_text,
                        char *resp_ct_ptr, size_t body_len)
{
    char *response_content = NULL;
    size_t write_offset = 0;
    size_t hdr_len = strlen(resp_hds_text);
    dbg_cp3_printf("resp_hds_text: %s\n", resp_hds_text);
    if (resp_ct_ptr != NULL)
    {
        response_content = resp_ct_ptr;
    }
    else if (resp_ct_text != NULL && resp_ct_text[0] != 0)
    {
        response_content = resp_ct_text;
        body_len = strlen(response_content);
    }
    else
    {
        response_content = NULL;
    }

    dbg_cp3_printf("response_content:\n%s\n", response_content);
    size_t hdr_attempt = 0;
    while (1)
    {
        hdr_attempt++;
        if (hdr_attempt > 1) {
            dbg_wselet_printf("hdr_attempt: %ld\n", hdr_attempt);
        }
        ssize_t write_ret = 0;
        write_ret = write(connfd, resp_hds_text + write_offset,
                          hdr_len);

        dbg_wselet_printf("write_ret: %d\n", write_ret);
        if (write_ret < 0)
        {
            dbg_wselet_printf("buffer full\n");
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                fprintf(logfp, "Failed writing content to socket on %d.\n",
                        connfd);
                fupdate(logfp);
                return -1;
            }
            else {
                write_ret = 0;
            }
        }

        if (write_ret == hdr_len)
        {
            break;
        }

        hdr_len = hdr_len - write_ret;
        write_offset = write_offset + write_ret;
    }
    if (response_content == NULL)
    {
        return 0;
    }
    write_offset = 0;
    size_t rsp_attempt = 0;
    while (1)
    {
        rsp_attempt++;
        if (rsp_attempt > 1) {
            dbg_wselet_printf("rsp_attempt: %ld\n", rsp_attempt);
        }
        ssize_t write_ret = 0;
        write_ret = write(connfd, response_content + write_offset,
                          body_len);
        dbg_wselet_printf("write_ret: %d\n", write_ret);
        if (write_ret < 0)
        {
            dbg_wselet_printf("buffer full\n");
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                fprintf(logfp, "Failed writing content to socket on %d.\n",
                        connfd);
                fupdate(logfp);
                return -1;
            }
            else {
                write_ret = 0;
            }
        }

        if (write_ret == body_len)
        {
            break;
        }

        body_len = body_len - write_ret;
        write_offset = write_offset + write_ret;
    }
    return 0;
}


void get_host_and_port(Requests *req_rover, char *hostname, char *port)
{
    size_t h_count = req_rover->h_count;
    Request_header *headers = req_rover->headers;
    size_t i = 0;
    for (i = 0; i < h_count; i++)
    {
        if (strcasecmp(headers[i].h_name, "Host") == 0)
        {
            strncpy(hostname, headers[i].h_value, 1023);
        }
    }
    if (hostname[0] == 0)
    {
        strncpy(hostname, req_rover->http_uri, 1023);
    }
    char *pos = strstr(hostname , ":");

    if (pos == NULL)
    {
        char *start = strstr(req_rover->http_uri , "http:");
        dbg_cp3_p3_printf("start: %p\n", start);
        if (start == NULL)
        {
            pos = strstr(req_rover->http_uri , ":");
        }
        else
        {
            // dbg_cp3_p3_printf("start: %s\n", start + 5);
            char *slash_pos = strstr(start + 5 , "/");
            pos = strstr(start + 5 , ":");
            if (slash_pos != NULL && pos > slash_pos)
            {
                pos = NULL;
            }
        }
    }
    else
    {
        *pos = 0;
    }

    if (pos == NULL)
    {
        strncpy(port, "80\0", 3);
    }
    else
    {
        strncpy(port, pos + 1, 1023);
        *pos = 0;
    }
    dbg_cp3_p3_printf("!!!!!!req_rover->http_uri: %s\n", req_rover->http_uri);
    dbg_cp3_p3_printf("!!!!!!host: %s\n", hostname);
    dbg_cp3_p3_printf("!!!!!!port: %s\n", port);
}

