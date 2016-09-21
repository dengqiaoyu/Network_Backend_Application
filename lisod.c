#include "lisod.h"

FILE *logfp = NULL;
int logfd = -1;

// ./lisod 2090 7114 ../tmp/lisod.log ../tmp/lisod.lock ../tmp/www ../tmp/cgi/cgi_script.py ../tmp/grader.key ../tmp/grader.crt

int main(int argc, char **argv)
{

    int listenfd, connfd, ret;
    socklen_t client_len;
    struct sockaddr_storage client_addr;
    static pools pool;
    parameters lisod_param;
    struct timeval timeout_select;
    struct timeval timeout_recv = {S_RECV_TIMEOUT, US_RECV_TIMEOUT};

    signal(SIGTSTP, sigtstp_handler);
    signal(SIGINT, sigtstp_handler);
    signal(SIGPIPE, SIG_IGN);

    dbg_cp2_printf("----- http1.1 Server -----\n");

    ret = check_argv(argc, argv, &lisod_param);
    if (ret < 0)
    {
        return -1;
    }

    //Temperary use
    strncpy(lisod_param.log_file, "./lisod.log\0", MAXLINE);
    dbg_cp2_printf("Settings:\n");
    dbg_cp2_printf("http_port: %s\n", lisod_param.http_port);
    dbg_cp2_printf("https_port: %s\n", lisod_param.https_port);
    dbg_cp2_printf("Log file: %s\n", lisod_param.log_file);
    dbg_cp2_printf("lock file: %s\n", lisod_param.lock_file);
    dbg_cp2_printf("www folder: %s\n", lisod_param.www_folder);
    dbg_cp2_printf("CGI script path: %s\n", lisod_param.cgi_script_path);
    dbg_cp2_printf("private key file: %s\n", lisod_param.private_key_file);
    dbg_cp2_printf("certificate file: %s\n", lisod_param.certificated_file);

    logfd = init_log(lisod_param.log_file, argc, argv);
    if (logfd < 0)
    {
        return -1;
    }
    logfp = fdopen(logfd, "a");

    if ((listenfd = open_listenfd(lisod_param.http_port)) < 0)
    {
        return -1;
    }
    init_pool(listenfd, &pool);

    dbg_cp2_printf("Listen port %d\n", atoi(argv[1]));

    while (1)
    {
        pool.ready_set = pool.active_set;
        timeout_select.tv_sec = S_SELECT_TIMEOUT;
        timeout_select.tv_usec = US_SELECT_TIMEOUT;
        pool.num_ready = select(pool.maxfd + 1, &pool.ready_set, NULL, NULL,
                                &timeout_select);

        if (FD_ISSET(listenfd, &pool.ready_set))
        {
            client_len = sizeof(struct sockaddr_storage);
            connfd = accept(listenfd, (struct sockaddr *)&client_addr,
                            &client_len);
            if (connfd < 0)
            {
                fprintf(logfp, "Failed accepting connection.\n");
                continue;
            }

            //ret = log_client(logfp, (struct sockaddr *)&client_addr, client_len);
            char client_hostname[MAXLINE], client_port[MAXLINE];
            int flags = NI_NUMERICHOST | NI_NUMERICSERV;
            ret = getnameinfo((struct sockaddr *)&client_addr, client_len,
                              client_hostname, MAXLINE,
                              client_port, MAXLINE, flags);
            if (ret != 0)
            {
                fprintf(logfp, "Can not resolve client's IP or port.\n");
            }
            else
            {
                fprintf(logfp, "Accept connection from client %s:%s.\n",
                        client_hostname, client_port);
            }

            ret = setsockopt(connfd, SOL_SOCKET, SO_RCVTIMEO,
                             (char *)&timeout_recv,
                             sizeof(struct timeval));
            if (ret < 0)
            {
                fprintf(logfp, "Failed setting timeout_recv.\n");
            }

            if (add_client(connfd, &pool) == -1)
            {
                fprintf(logfp, "add_client Failed.\n");
            }
        }

        if (server_clients(&pool) < 0)
        {
            fprintf(logfp, "server_clients Failed.\n");
        }
    }

    ret = fclose(logfp);
    if (ret != 0)
    {
        fprintf(stderr, "Failed close file pointer.\n");
        exit(1);
    }
    return 0;
}

void sigtstp_handler()
{
    int ret;

    fprintf(logfp, "Terminated by user.\n");
    fprintf(logfp, "-------------------------------------------------------\n");
    fprintf(logfp, "*           EndTime: %s         *\n", get_current_time());
    fprintf(logfp, "*******************************************************\n");
    ret = fclose(logfp);
    if (ret != 0)
    {
        fprintf(stderr, "Failed close file pointer.\n");
        exit(1);
    }
    dbg_cp2_printf("\nTerminated by user.\n");
    exit(1);
}

int check_argv(int argc, char **argv, parameters *lisod_param)
{
    if (argc < 4)
    {
        fprintf(stderr, "Usage: %s ", argv[0]);
        fprintf(stderr, "<HTTP port> ");
        fprintf(stderr, "<HTTPS port> ");
        fprintf(stderr, "<log file> ");
        fprintf(stderr, "<lock file> ");
        fprintf(stderr, "<www folder> ");
        fprintf(stderr, "<CGI script path> ");
        fprintf(stderr, "<private key file> ");
        fprintf(stderr, "<certificate file>\n");
        return -1;
    }

    if (atoi(argv[1]) < 1024 || atoi(argv[1]) > 65535)
    {
        fprintf(stderr, "Usage: HTTP port should be between 1024 and 65535.");
        return -1;
    }
    else
    {
        strncpy(lisod_param->http_port, argv[1], MAXLINE);
        lisod_param->http_port[MAXLINE - 1] = '\0';
    }

    if (atoi(argv[2]) < 1024 || atoi(argv[2]) > 65535)
    {
        fprintf(stderr, "Usage: HTTPs port should be between 1024 and 65535.");
        return -1;
    }
    else
    {
        strncpy(lisod_param->https_port, argv[2], MAXLINE);
        lisod_param->https_port[MAXLINE - 1] = '\0';
    }

    if (strlen(argv[3]) >= MAXLINE)
    {
        fprintf(stderr, "Log file path too long.");
        return -1;
    }
    else
    {
        strncpy(lisod_param->log_file, argv[3], MAXLINE);
        lisod_param->log_file[MAXLINE - 1] = '\0';
    }

    if (strlen(argv[4]) >= MAXLINE)
    {
        fprintf(stderr, "Lock file path too long.");
        return -1;
    }
    else
    {
        strncpy(lisod_param->lock_file, argv[4], MAXLINE);
        lisod_param->lock_file[MAXLINE - 1] = '\0';
    }

    if (strlen(argv[5]) >= MAXLINE)
    {
        fprintf(stderr, "WWW folder too long.");
        return -1;
    }
    else
    {
        strncpy(lisod_param->www_folder, argv[5], MAXLINE);
        lisod_param->www_folder[MAXLINE - 1] = '\0';
    }

    if (strlen(argv[6]) >= MAXLINE)
    {
        fprintf(stderr, "CGI script path too long.");
        return -1;
    }
    else
    {
        strncpy(lisod_param->cgi_script_path, argv[6], MAXLINE);
        lisod_param->cgi_script_path[MAXLINE - 1] = '\0';
    }

    if (strlen(argv[7]) >= MAXLINE)
    {
        fprintf(stderr, "Private key file path too long.");
        return -1;
    }
    else
    {
        strncpy(lisod_param->private_key_file, argv[7], MAXLINE);
        lisod_param->private_key_file[MAXLINE - 1] = '\0';
    }

    if (strlen(argv[8]) >= MAXLINE)
    {
        fprintf(stderr, "Certificated file path too long.");
        return -1;
    }
    else
    {
        strncpy(lisod_param->certificated_file, argv[8], MAXLINE);
        lisod_param->certificated_file[MAXLINE - 1] = '\0';
    }
    return 0;
}

int open_listenfd(char *port)
{
    struct addrinfo hints, *listp, *p;
    int listenfd, optval = 1;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE | AI_ADDRCONFIG;
    hints.ai_flags |= AI_NUMERICSERV;
    if (getaddrinfo(NULL, port, &hints, &listp) != 0)
    {
        fprintf(logfp, "Failed getting address information.\n");
        return -1;
    }

    for (p = listp; p; p = p->ai_next)
    {
        listenfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (listenfd < 0)
        {
            continue;
        }

        if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR,
                       (const void *)&optval, sizeof(int)) < 0)
        {
            continue;
        }

        if (bind(listenfd, p->ai_addr, p->ai_addrlen) == 0)
        {
            break;
        }
        else
        {
            if (close(listenfd) < 0)
            {
                fprintf(logfp, "Failed closing listening file descriptor.\n");
                return -1;
            }
        }
    }

    freeaddrinfo(listp);
    if (!p)
    {
        fprintf(logfp, "No address worked.\n");
        return -1;
    }

    if (listen(listenfd, LISTENQ) < 0)
    {
        if (close(listenfd) < 0)
        {
            fprintf(logfp, "Failed closing listening file descriptor.\n");
            return -1;
        }
        fprintf(logfp, "Failed listening on socket.\n");
        return -1;
    }

    return listenfd;
}

void init_pool(int listenfd, pools *p)
{
    int i;

    p->maxi = -1;
    p->maxfd = listenfd;
    FD_ZERO(&p->active_set);
    FD_SET(listenfd, &p->active_set);
    for (i = 0; i < FD_SETSIZE; i++)
    {
        p->clientfd[i] = -1;
        p->if_ignore_first[i] = -1;
        p->if_too_long[i] = -1;
        memset(p->cached_buffer[i], 0, REQUEST_BUF_SIZE + 1);
    }

}

int add_client(int connfd, pools *p)
{
    int i;

    p->num_ready--;

    for (i = 0; i < FD_SETSIZE; i++)
    {
        if (p->clientfd[i] < 0)
        {
            p->clientfd[i] = connfd;
            p->if_ignore_first[connfd] = 0;
            p->if_too_long[connfd] = 0;
            memset(p->cached_buffer[connfd], 0, REQUEST_BUF_SIZE + 1);
            FD_SET(connfd, &p->active_set);

            if (connfd > p->maxfd)
            {
                p->maxfd = connfd;
            }
            if (i > p->maxi)
            {
                p->maxi = i;
            }
            break;
        }
    }
    if (i == FD_SETSIZE)
    {
        if (close(connfd) < 0)
        {
            fprintf(logfp, "Failed closing connection file descriptor.\n");
            return -1;
        }
        fprintf(logfp, "Failed adding connection file descriptor.\n");
        return -2;
    }

    return 0;
}

int server_clients(pools *p)
{
    int i, connfd, read_ret, read_or_not, write_ret, write_offset;
    char socket_recv_buf[SOCKET_RECV_BUF_SIZE + 1];
    struct timeval tv_out;

    for (i = 0; (i <= p->maxi) && (p->num_ready > 0); i++)
    {
        connfd = p->clientfd[i];

        if ((connfd > 0) && (FD_ISSET(connfd, &p->ready_set)))
        {
            p->num_ready--;

            read_or_not = 1;
            while (read_or_not)
            {
                memset(socket_recv_buf, 0, SOCKET_RECV_BUF_SIZE + 1);
                read_ret = recv(connfd, socket_recv_buf, SOCKET_RECV_BUF_SIZE,
                                MSG_WAITALL);
                dbg_cp1_printf("read_ret: %d\n", read_ret);
                if (read_ret < 0)
                {
                    fprintf(logfp, "Failed receiving data from fd %d.\n",
                            connfd);
                    if (close(connfd) < 0)
                    {
                        fprintf(logfp, "Failed closing connection ");
                        fprintf(logfp, "file descriptor.\n");
                        return -1;
                    }
                    FD_CLR(connfd, &p->active_set);
                    p->clientfd[i] = -1;
                    break;
                }
                else if (read_ret == 0)
                {
                    if (close(connfd) < 0)
                    {
                        fprintf(logfp, "Failed closing connection ");
                        fprintf(logfp, "file descriptor.\n");
                        return -1;
                    }
                    FD_CLR(connfd, &p->active_set);
                    p->clientfd[i] = -1;
                    break;
                }
                if (read_ret == sizeof(socket_recv_buf))
                {
                    dbg_cp1_printf("again!\n");
                    read_or_not = 1;
                }
                else
                    read_or_not = 0;
                //dbg_cp2_printf("socket_recv_buf in lisod.c:[\n%s]\n", socket_recv_buf);
                Requests *requests = parse(socket_recv_buf, read_ret, connfd, p);
                // dbg_cp2_printf("parse complete!\n");
                print_request(requests);
                destory_requests(requests);
                requests = NULL;
                send(connfd, "HTTP/1.1 204 No Content\r\n", 64, MSG_WAITALL);
                send(connfd, "Server: bfe/1.0.8.18\r\n", 64, MSG_WAITALL);
                send(connfd, "\r\n", 64, MSG_WAITALL);
                Close_connection(connfd, i, p);

                //exit(1);
                /*write_offset = 0;
                while (1)
                {
                    write_ret = send(connfd, socket_recv_buf + write_offset, read_ret,
                                     MSG_WAITALL);
                    dbg_cp1_printf("write_ret: %d\n", write_ret);
                    if (write_ret < 0)
                    {
                        if (close(connfd) < 0)
                        {
                            fprintf(logfp, "Failed closing connection ");
                            fprintf(logfp, "file descriptor.\n");
                            return -1;
                        }
                        FD_CLR(connfd, &p->active_set);
                        p->clientfd[i] = -1;
                        break;
                    }

                    if (write_ret == read_ret)
                    {
                        dbg_cp1_printf("completed!\n");
                        break;
                    }

                    read_ret = read_ret - write_ret;
                    write_offset = write_offset + write_ret;
                }*/
            }
        }
    }

    return 0;
}

void destory_requests(Requests *requests)
{
    Requests *request_rover = requests;
    while (request_rover != NULL)
    {
        Requests *next_request = request_rover->next_request;
        free(request_rover->headers);
        request_rover->headers = NULL;
        free(request_rover);
        request_rover = next_request;
    }
}

void print_request(Requests *requests)
{
    Requests *request_rover = requests;
    int index = 0;
    while (request_rover != NULL)
    {
        int index;
        printf("Http Method %s\n", request_rover->http_method);
        printf("Http Version %s\n", request_rover->http_version);
        printf("Http Uri %s\n", request_rover->http_uri);
        for (index = 0; index < request_rover->header_count; index++) {
            printf("Request Header\n");
            printf("Header name %s Header Value %s\n",
                   request_rover->headers[index].header_name,
                   request_rover->headers[index].header_value);
        }
        printf("**********************************************************\n");
        request_rover = request_rover->next_request;
    }
}

int Close_connection(int connfd, int index, pools *p)
{
    close(connfd);
    if (close(connfd) < 0)
    {
        fprintf(logfp, "Failed closing connection ");
        fprintf(logfp, "file descriptor.\n");
        return -1;
    }
    FD_CLR(connfd, &p->active_set);
    p->clientfd[index] = -1;
    p->if_ignore_first[connfd] = 0;
    p->if_too_long[connfd] = 0;
    memset(p->cached_buffer[connfd], 0, REQUEST_BUF_SIZE + 1);
    return 0;
}