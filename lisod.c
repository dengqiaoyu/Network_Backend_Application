#include "lisod.h"

FILE *logfp = NULL;
int logfd = -1;

// ./lisod 2090 7114 ../tmp/lisod.log ../tmp/lisod.lock ../tmp/www ../tmp/cgi/cgi_script.py ../tmp/grader.key ../tmp/grader.crt

static const char *FILE_SUFFIX[TYPE_SIZE] =
{ ".html", ".css", ".gif", ".png", ".jpg"};

static const char *FILE_TYPE[TYPE_SIZE] =
{ "text/html", "text/css", "image/gif", "image/png", "image/jpeg"};

parameters lisod_param;

void printf_request_analyzed(Request_analyzed *request_analyzed);

int main(int argc, char **argv)
{

    int listenfd, connfd, ret;
    socklen_t client_len;
    struct sockaddr_storage client_addr;
    static pools pool;
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

            if (add_client(connfd, &pool, client_hostname) == -1)
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
    fprintf(logfp, "------------------------------------------------------\n");
    fprintf(logfp, "*           EndTime: %s         *\n", get_current_time());
    fprintf(logfp, "******************************************************\n");
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

int add_client(int connfd, pools *p, char *client_hostname)
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
            strncpy(p->client_ip[connfd], client_hostname, MAX_SIZE_SMALL);

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
    int i, connfd, read_ret, read_or_not, ret;
    char socket_recv_buf[SOCKET_RECV_BUF_SIZE + 1];
    //struct timeval tv_out;

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
                dbg_cp2_printf("socket_recv_buf in lisod.c:[\n%s]\n", socket_recv_buf);
                Requests *requests = parse(socket_recv_buf, read_ret, connfd, p);
                dbg_cp2_printf("parse complete!\n");

                Requests *request_rover = requests;
                print_request(request_rover);
                request_rover = requests;

                while (request_rover != NULL)
                {
                    Request_analyzed request_analyzed;
                    get_request_analyzed(&request_analyzed, request_rover);
                    fprintf(logfp, "Get %s request from %s.\n",
                            request_rover->http_method, p->client_ip[connfd]);
                    fprintf(logfp, "    User-Agent: %s\n",
                            request_analyzed.user_agent);
                    printf_request_analyzed(&request_analyzed);
                    dbg_cp2_printf("get_request_analyzed complete!\n");
                    ret = send_response(&request_analyzed, request_rover,
                                        connfd);
                    if (ret != 0)
                    {
                        Close_connection(connfd, i, p);
                        break;
                    }
                    request_rover = request_rover->next_request;
                }
                destory_requests(requests);
                requests = NULL;
            }
        }
    }

    return 0;
}

void get_request_analyzed(Request_analyzed *request_analyzed,
                          Requests *request)
{
    int index = 0;
    int ret = 0;
    // memset(request_analyzed->connection, 0, MAX_SIZE_SMALL);
    // memset(request_analyzed->accept_charset, 0, MAX_SIZE_SMALL);
    // memset(request_analyzed->accept_encoding, 0, MAX_SIZE_SMALL);
    // memset(request_analyzed->accept_language, 0, MAX_SIZE_SMALL);
    // memset(request_analyzed->host, 0, MAX_SIZE);
    // memset(request_analyzed->user_agent, 0, MAX_SIZE);

    memset(request_analyzed, 0, sizeof(Request_analyzed));

    for (index = 0; index < request->header_count; index++)
    {
        ret = strncasecmp("connection", request->headers[index].header_name,
                          MAX_SIZE);
        if (!ret)
        {
            strncpy(request_analyzed->connection,
                    request->headers[index].header_value, MAX_SIZE_SMALL);
            request_analyzed->connection[MAX_SIZE_SMALL - 1] = 0;
        }

        ret = strncasecmp("accept-charset",
                          request->headers[index].header_name,
                          MAX_SIZE);
        if (!ret)
        {
            strncpy(request_analyzed->accept_charset,
                    request->headers[index].header_value, MAX_SIZE_SMALL);
            request_analyzed->accept_charset[MAX_SIZE_SMALL - 1] = 0;
        }

        ret = strncasecmp("accept-encoding", request->headers[index].header_name,
                          MAX_SIZE);
        if (!ret)
        {
            strncpy(request_analyzed->accept_encoding,
                    request->headers[index].header_value, MAX_SIZE_SMALL);
            request_analyzed->accept_encoding[MAX_SIZE_SMALL - 1] = 0;
        }

        ret = strncasecmp("accept-language", request->headers[index].header_name,
                          MAX_SIZE);
        if (!ret)
        {
            strncpy(request_analyzed->accept_language,
                    request->headers[index].header_value, MAX_SIZE_SMALL);
            request_analyzed->accept_language[MAX_SIZE_SMALL - 1] = 0;
        }

        ret = strncasecmp("host", request->headers[index].header_name,
                          MAX_SIZE);
        if (!ret)
        {
            strncpy(request_analyzed->host,
                    request->headers[index].header_value, MAX_SIZE_SMALL);
            request_analyzed->host[MAX_SIZE_SMALL - 1] = 0;
        }

        ret = strncasecmp("user-agent", request->headers[index].header_name,
                          MAX_SIZE);
        if (!ret)
        {
            strncpy(request_analyzed->user_agent,
                    request->headers[index].header_value, MAX_SIZE);
            request_analyzed->user_agent[MAX_SIZE - 1] = 0;
        }
    }
}

int send_response(Request_analyzed *request_analyzed, Requests *request,
                  int connfd)
{
    int status_code;
    Response_headers response_headers;
    char response_headers_text[MAX_TEXT];
    char response_content_text[MAX_TEXT];
    int contentfd, ret;
    size_t content_size;
    char *response_content_ptr = NULL;
    int if_close_connnection = 0;
    memset(&response_headers, 0, sizeof(Response_headers));
    memset(response_headers_text, 0, MAX_TEXT);
    memset(response_content_text, 0, MAX_TEXT);


    if (strncmp("HTTP/1.0", request->http_version, MAX_SIZE_SMALL) != 0
            && strncmp("HTTP/1.1", request->http_version, MAX_SIZE_SMALL) != 0)
    {
        status_code = 505;
    }
    strncpy(response_headers.status_line.http_version, "HTTP/1.1",
            MAX_SIZE_SMALL);
    strncpy(response_headers.general_header.cache_control, "no-cache",
            MAX_SIZE_SMALL);
    if (!strncmp("close", request_analyzed->connection, MAX_SIZE_SMALL))
    {
        strncpy(response_headers.general_header.connection, "close",
                MAX_SIZE_SMALL);
        if_close_connnection = 1;
    }
    else
    {
        strncpy(response_headers.general_header.connection, "keep-alive",
                MAX_SIZE_SMALL);
    }

    char *time_GMT = get_rfc1123_date();
    strncpy(response_headers.general_header.date, time_GMT,
            MAX_SIZE_SMALL);
    free(time_GMT);
    strncpy(response_headers.general_header.paragma, "no-cache",
            MAX_SIZE_SMALL);
    strncpy(response_headers.general_header.transfer_encoding, "identity",
            MAX_SIZE_SMALL);
    strncpy(response_headers.response_header.server, "lisod-qdeng",
            MAX_SIZE_SMALL);
    strncpy(response_headers.entity_header.allow, "GET, HEAD",
            MAX_SIZE_SMALL);
    strncpy(response_headers.entity_header.content_encoding, "identity",
            MAX_SIZE_SMALL);
    strncpy(response_headers.entity_header.content_language, "en",
            MAX_SIZE_SMALL);
    //dbg_cp2_printf("line 591\n");
    //print_response_headers(&response_headers);

    status_code = check_http_method(request->http_method);

    if (status_code == 200)
    {
        //dbg_cp2_printf("line 601\n");
        status_code = get_contentfd(request, &response_headers, &contentfd);
        //dbg_cp2_printf("status_code: %d\n", status_code);
        if (status_code == 200)
        {
            //dbg_cp2_printf("line 605\n");
            //print_response_headers(&response_headers);
            //dbg_cp2_printf("line 607\n");
            get_response_headers(response_headers_text, &response_headers);
        }
        //dbg_cp2_printf("response_headers_text:[\n%s]\n", response_headers_text);
        //exit(1);
    }

    if (status_code != 200)
    {
        get_error_content(status_code, response_content_text,
                          &response_headers);
        get_response_headers(response_headers_text, &response_headers);
        //dbg_cp2_printf("response_headers_text:[\n%s]\n", response_headers_text);
        //dbg_cp2_printf("response_content_text:[\n%s]\n", response_content_text);
        //dbg_cp2_printf("line 617\n");
        //exit(1);
    }

    if (status_code == 200)
    {
        content_size = response_headers.entity_header.content_length;
        response_content_ptr = mmap(0, content_size, PROT_READ, MAP_PRIVATE,
                                    contentfd, 0);
        if (response_content_ptr == (void *)(-1))
        {
            fprintf(logfp, "Failed mapping request file.\n");
            status_code = 500;
        }
        if (close(contentfd) < 0)
        {
            fprintf(logfp, "Failed closing content ");
            fprintf(logfp, "file descriptor.\n");
        }
    }

    if (!strncmp(request->http_method, "HEAD", MAX_SIZE_SMALL))
    {
        ret = write_to_socket(status_code, response_headers_text,
                              response_content_text, NULL, 0,
                              connfd);
    }
    else
    {
        dbg_cp2_printf("line 648\n");
        ret = write_to_socket(status_code, response_headers_text,
                              response_content_text, response_content_ptr,
                              response_headers.entity_header.content_length,
                              connfd);
    }

    if (status_code == 200)
    {
        ret = munmap(response_content_ptr, content_size);
        if (ret == -1)
        {
            fprintf(logfp, "Failed unmapping request file.\n");
        }
    }

    dbg_cp2_printf("ret: %d\n", ret);
    dbg_cp2_printf("if_close_connnection: %d\n", if_close_connnection);
    return ret - if_close_connnection;
}

int check_http_method(char *http_method)
{
    int status_code;
    if (!strncmp("GET", http_method, MAX_SIZE_SMALL))
    {
        status_code = 200;
    }
    else if (!strncmp("HEAD", http_method, MAX_SIZE_SMALL))
    {
        status_code = 200;
    }
    else if (!strncmp("POST", http_method, MAX_SIZE_SMALL))
    {
        status_code = 200;
    }
    else
    {
        status_code = 501;
    }

    return status_code;
}

void get_response_headers(char *response_headers_text,
                          Response_headers *response_headers)
{
    char text_tmp[MAX_TEXT] = {0};
    size_t text_len = 0;
    snprintf(text_tmp, MAX_TEXT, "%s %s %s\r\n",
             response_headers->status_line.http_version,
             response_headers->status_line.status_code,
             response_headers->status_line.reason_phrase);
    strncat(response_headers_text, text_tmp,
            MAX_TEXT - text_len);
    text_len +=  strlen(text_tmp);
    snprintf(text_tmp, MAX_TEXT, "Cache-Control: %s\r\n",
             response_headers->general_header.cache_control);
    strncat(response_headers_text, text_tmp,
            MAX_TEXT - text_len);
    text_len +=  strlen(text_tmp);
    snprintf(text_tmp, MAX_TEXT, "Connection: %s\r\n",
             response_headers->general_header.connection);
    strncat(response_headers_text, text_tmp,
            MAX_TEXT - text_len);
    text_len +=  strlen(text_tmp);
    snprintf(text_tmp, MAX_TEXT, "Date: %s\r\n",
             response_headers->general_header.date);
    strncat(response_headers_text, text_tmp,
            MAX_TEXT - text_len);
    text_len +=  strlen(text_tmp);
    snprintf(text_tmp, MAX_TEXT, "Paragma: %s\r\n",
             response_headers->general_header.paragma);
    strncat(response_headers_text, text_tmp,
            MAX_TEXT - text_len);
    text_len +=  strlen(text_tmp);
    snprintf(text_tmp, MAX_TEXT, "Transfer-Encoding: %s\r\n",
             response_headers->general_header.transfer_encoding);
    strncat(response_headers_text, text_tmp,
            MAX_TEXT - text_len);
    text_len +=  strlen(text_tmp);
    snprintf(text_tmp, MAX_TEXT, "Server: %s\r\n",
             response_headers->response_header.server);
    strncat(response_headers_text, text_tmp,
            MAX_TEXT - text_len);
    text_len +=  strlen(text_tmp);
    snprintf(text_tmp, MAX_TEXT, "Allow: %s\r\n",
             response_headers->entity_header.allow);
    strncat(response_headers_text, text_tmp,
            MAX_TEXT - text_len);
    text_len +=  strlen(text_tmp);
    snprintf(text_tmp, MAX_TEXT, "Content-Encoding: %s\r\n",
             response_headers->entity_header.content_encoding);
    strncat(response_headers_text, text_tmp,
            MAX_TEXT - text_len);
    text_len +=  strlen(text_tmp);
    snprintf(text_tmp, MAX_TEXT, "Content-Language: %s\r\n",
             response_headers->entity_header.content_language);
    strncat(response_headers_text, text_tmp,
            MAX_TEXT - text_len);
    text_len +=  strlen(text_tmp);
    snprintf(text_tmp, MAX_TEXT, "Content-Length: %d\r\n",
             response_headers->entity_header.content_length);
    strncat(response_headers_text, text_tmp,
            MAX_TEXT - text_len);
    text_len +=  strlen(text_tmp);
    snprintf(text_tmp, MAX_TEXT, "Content-Type: %s\r\n",
             response_headers->entity_header.content_type);
    strncat(response_headers_text, text_tmp,
            MAX_TEXT - text_len);
    text_len +=  strlen(text_tmp);
    snprintf(text_tmp, MAX_TEXT, "Last-Modified: %s\r\n",
             response_headers->entity_header.last_modified);
    strncat(response_headers_text, text_tmp,
            MAX_TEXT - text_len);
    text_len +=  strlen(text_tmp);
    strncat(response_headers_text, "\r\n", MAX_TEXT - text_len);
}

void get_error_content(int status_code, char *body,
                       Response_headers *response_headers)
{
    char shortmsg[MAX_TEXT];
    char cause[MAX_TEXT];
    switch (status_code)
    {
    case 400:
        strncpy(shortmsg, "Bad Request", MAX_TEXT);
        strncpy(cause, "The request could not be understood by the server due to malformed syntax.",
                MAX_TEXT);
        break;
    case 403:
        strncpy(shortmsg, "Forbidden", MAX_TEXT);
        strncpy(cause, "The server understood the request, but is refusing to fulfill it.",
                MAX_TEXT);
        break;
    case 404:
        strncpy(shortmsg, "Not Found", MAX_TEXT);
        strncpy(cause, "The server has not found anything matching the Request-URI.",
                MAX_TEXT);
        break;
    case 501:
        strncpy(shortmsg, "Not Implemented", MAX_TEXT);
        strncpy(cause, "The server does not support the functionality required to fulfill the request.",
                MAX_TEXT);
        break;
    case 505:
        strncpy(shortmsg, "HTTP Version Not Supported", MAX_TEXT);
        strncpy(cause, "The server does not support, or refuses to support, the HTTP protocol version that was used in the request message.",
                MAX_TEXT);
        break;
    }
    snprintf(response_headers->status_line.status_code, MAX_SIZE_SMALL, "%d",
             status_code);
    strncpy(response_headers->status_line.reason_phrase,
            shortmsg, MAX_SIZE_SMALL);
    strncpy(response_headers->entity_header.content_type,
            "text/html", MAX_SIZE_SMALL);

    sprintf(body, "<html>");
    sprintf(body, "%s<head><title>Opps</title></head>\r\n", body);
    sprintf(body, "%s<body bgcolor=""ffffff"">\r\n", body);
    sprintf(body, "%s<p>%d: %s</p>\r\n", body, status_code, shortmsg);
    sprintf(body, "%s<p>%s</p>\r\n", body, cause);
    sprintf(body, "%s<hr /><em>The http1.1 Server By qdeng</em>\r\n", body);
    sprintf(body, "%s</body>\r\n", body);
    sprintf(body, "%s</html>\r\n", body);
    char *time_GMT = get_rfc1123_date();
    strncpy(response_headers->entity_header.last_modified, time_GMT,
            MAX_SIZE_SMALL);
    free(time_GMT);
    response_headers->entity_header.content_length = strlen(body);
}

int get_contentfd(Requests *request, Response_headers *response_headers,
                  int *contentfd)
{
    int status_code = 0;
    char file_name[MAX_SIZE];
    char file_type[MAX_SIZE];
    struct stat sbuf;
    memset(file_name, 0, MAX_SIZE);
    memset(file_type, 0, MAX_SIZE);
    strncpy(file_name, request->http_uri, MAX_SIZE - 1);

    status_code = decode_asc(request->http_uri);

    if (status_code != 200)
    {
        *contentfd = -1;
        return status_code;
    }
    //dbg_cp2_printf("line 795, http_uri: %s\n", &request->http_uri[1]);
    dbg_cp2_printf("line 832, status_code: %d\n", status_code);
    status_code = convert2path(request->http_uri);
    dbg_cp2_printf("line 834, status_code: %d\n", status_code);
    //dbg_cp2_printf("line 797, http_uri: %s\n", &request->http_uri[1]);
    //dbg_cp2_printf("line 798, status_code: %d\n", status_code);
    if (status_code != 200)
    {
        *contentfd = -1;
        return status_code;
    }

    if (!strncmp(request->http_uri, "/", MAX_SIZE) || \
            !strncmp(request->http_uri, "", MAX_SIZE))
    {
        char path_home[MAX_SIZE] = {0};
        char path_index[MAX_SIZE] = {0};
        snprintf(path_home, MAX_SIZE, "%s%s\0", lisod_param.www_folder, "/home.html");
        //dbg_cp2_printf("path_home: %s\n", path_home);
        snprintf(path_index, MAX_SIZE, "%s%s\0", lisod_param.www_folder, "/index.html");
        //dbg_cp2_printf("path_index: %s\n", path_index);
        if (stat(path_home, &sbuf) == 0)
        {
            strncpy(request->http_uri, path_home, MAX_SIZE - 1);
        }
        else if (stat(path_index, &sbuf) == 0)
        {
            strncpy(request->http_uri, path_index, MAX_SIZE - 1);
        }
        //dbg_cp2_printf("line 822, file_name: %s\n", file_name);
    }
    else
    {
        //dbg_cp2_printf("line 826, file_name: %s\n", file_name);
        strncpy(request->http_uri, request->http_uri, MAX_SIZE - 1);
    }
    //dbg_cp2_printf("line 829, file_name: %s\n", request->http_uri);
    snprintf(file_name, MAX_SIZE, "%s", request->http_uri);
    //dbg_cp2_printf("line 831, file_name: %s\n", file_name);
    if (stat(file_name, &sbuf) < 0)
    {
        status_code = 404;
        *contentfd = -1;
        return status_code;
    }

    if (!(S_ISREG(sbuf.st_mode)) || !(S_IRUSR & sbuf.st_mode))
    {
        status_code = 403;
        *contentfd = -1;
        return status_code;
    }
    //dbg_cp2_printf("line 845\n");
    if (!strncmp(request->http_method, "POST", MAX_SIZE_SMALL))
    {
        //TODO
    }
    else
    {
        //dbg_cp2_printf("line 852\n");
        status_code = get_file_type(file_name, file_type);
        //dbg_cp2_printf("file_type: %s\n", file_type);
        response_headers->entity_header.content_length = sbuf.st_size;
        strncpy(response_headers->entity_header.content_type,
                file_type, MAX_SIZE_SMALL);
        *contentfd = open(file_name, O_RDONLY, 0);
        if (*contentfd == -1)
        {
            fprintf(logfp, "Failed opening file %s.\n", file_name);
            status_code = 403;
            return status_code;
        }
        char *last_modified = NULL;
        last_modified = get_last_modified_date(&sbuf.st_mtime);
        snprintf(response_headers->entity_header.last_modified, MAX_SIZE_SMALL, "%s",
                 last_modified);
        free(last_modified);
    }

    status_code = 200;
    strncpy(response_headers->status_line.reason_phrase,
            "OK", MAX_SIZE_SMALL);
    snprintf(response_headers->status_line.status_code, MAX_SIZE_SMALL, "%d",
             status_code);
    //print_response_headers(response_headers);
    return status_code;
}

int get_file_type(char *file_name, char *file_type)
{
    int i;
    for (i = 0; i < TYPE_SIZE; i++)
    {
        int index = search_last_position(".", file_name);
        if (strstr(&file_name[index], FILE_SUFFIX[i]) != NULL)
        {
            strncpy(file_type, FILE_TYPE[i], strlen(FILE_TYPE[i]));
        }
    }
    if (file_type[0] == 0)
    {
        strncpy(file_type, "text/plain", strlen("text/plain"));
    }

    return 200;
}

int write_to_socket(int status_code, char *response_headers_text,
                    char *response_content_text, char *response_content_ptr,
                    size_t content_size, int connfd)
{
    char *response_content = NULL;
    size_t write_offset = 0;
    size_t headers_size = strlen(response_headers_text);
    if (status_code == 200)
    {
        response_content = response_content_ptr;
    }
    else
    {
        response_content = response_content_text;
    }
    dbg_cp2_printf("response_content:\n%s\n", response_content);
    while (1)
    {
        int write_ret = send(connfd, response_headers_text + write_offset,
                             headers_size, MSG_WAITALL);
        //dbg_cp2_printf("write_ret: %d\n", write_ret);
        if (write_ret < 0)
        {
            fprintf(logfp, "Failed writing headers to socket on %d.\n",
                    connfd);
            return -1;
        }

        if (write_ret == headers_size)
        {
            //dbg_cp2_printf("completed!\n");
            break;
        }

        headers_size = headers_size - write_ret;
        write_offset = write_offset + write_ret;
    }
    dbg_cp2_printf("line 982\n");
    if (response_content_ptr == NULL)
        content_size = strlen(response_content);
    write_offset = 0;
    while (1)
    {
        int write_ret = send(connfd, response_content + write_offset,
                             content_size, MSG_WAITALL);
        //dbg_cp2_printf("write_ret: %d\n", write_ret);
        if (write_ret < 0)
        {
            fprintf(logfp, "Failed writing content to socket on %d.\n",
                    connfd);
            return -1;
        }

        if (write_ret == content_size)
        {
            //dbg_cp2_printf("completed!\n");
            break;
        }

        content_size = content_size - write_ret;
        write_offset = write_offset + write_ret;
    }

    return 0;
}

int decode_asc(char *str)
{
    char str_decoded[MAX_SIZE];
    memset(str_decoded, 0, MAX_SIZE);
    size_t length = strlen(str);
    size_t i, j;
    j = 0;
    for (i = 0; i < length - 2;)
    {
        if (str[i] == '%')
        {
            char ch = 0;
            if (str[i + 1] > 64 && str[i + 1] < 71)
            {
                ch = (str[i + 1] - 55) * 16;
            }
            else if (str[i + 1] > 96 && str[i + 1] < 103)
            {
                ch = (str[i + 1] - 87) * 16;
            }
            else if (str[i + 1] > 47 && str[i + 1] < 58)
            {
                ch = (str[i + 1] - 48) * 16;
            }
            else
            {
                return 400;
            }

            if (str[i + 2] > 64 && str[i + 2] < 71)
            {
                ch += str[i + 2] - 55;
            }
            else if (str[i + 2] > 96 && str[i + 2] < 103)
            {
                ch += str[i + 2] - 87;
            }
            else if (str[i + 2] > 47 && str[i + 2] < 58)
            {
                ch += str[i + 2] - 48;
            }
            else
            {
                return 400;
            }

            str_decoded[j] = ch;
            j++;
            i += 3;
        }
        else
        {
            str_decoded[j] = str[i];
            j++;
            i++;
        }
    }

    if (str[i - 1] != '%')
    {
        str_decoded[j] = str[i];
        str_decoded[j + 1] = str[i + 1];
    }

    strncpy(str, str_decoded, MAX_SIZE - 1);
    return 200;
}

int convert2path(char *uri)
{
    size_t slash_num = 0;
    size_t uri_len = strlen(uri);
    char uri_buf[MAX_SIZE] = {0};
    size_t i = 0;

    for (i = 0; i < uri_len; i++)
    {
        if (uri[i] == '/')
            slash_num++;
    }
    if (strstr(uri, "http://") != uri)
    {
        dbg_cp2_printf("line 1084\n");
        dbg_cp2_printf("uri: %s\n", uri);
        if ((strstr(uri, "/") != uri))
        {
            dbg_cp2_printf("line 1087\n");
            if (strncmp(uri, "", MAX_SIZE) != 0)
            {
                return 400;
            }
            else
            {
                return 200;
            }
        }
        else
        {
            return 200;
        }
    }
    else if (slash_num < 3)
    {
        return 400;
    }
    else
    {
        char *start = strstr(&uri[7], "/");
        strncpy(uri_buf, start, MAX_SIZE);
        strncpy(uri, uri_buf, MAX_SIZE);
        return 200;
    }
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
    while (request_rover != NULL)
    {
        int index = 0;
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
    char buf[1];
    int if_close = recv(connfd, buf, 1, MSG_PEEK);
    int sock_error = errno;

    if (if_close > 0)
    {
        if (close(connfd) < 0)
        {
            fprintf(logfp, "Failed closing connection ");
            fprintf(logfp, "file descriptor.\n");
        }
    }
    else if ((if_close == -1) && (sock_error == EWOULDBLOCK))
    {
        if (close(connfd) < 0)
        {
            fprintf(logfp, "Failed closing connection ");
            fprintf(logfp, "file descriptor.\n");
        }
    }

    FD_CLR(connfd, &p->active_set);
    p->clientfd[index] = -1;
    p->if_ignore_first[connfd] = 0;
    p->if_too_long[connfd] = 0;
    memset(p->cached_buffer[connfd], 0, REQUEST_BUF_SIZE + 1);
    memset(p->client_ip[connfd], 0, MAX_SIZE_SMALL);
    return 0;
}

void printf_request_analyzed(Request_analyzed *request_analyzed)
{
    dbg_cp2_printf("connection: %s\n", request_analyzed->connection);
    dbg_cp2_printf("accept_charset: %s\n", request_analyzed->accept_charset);
    dbg_cp2_printf("accept_encoding: %s\n", request_analyzed->accept_encoding);
    dbg_cp2_printf("accept_language: %s\n", request_analyzed->accept_language);
    dbg_cp2_printf("host: %s\n", request_analyzed->host);
    dbg_cp2_printf("user_agent: %s\n", request_analyzed->user_agent);
}

print_response_headers(Response_headers *response_headers)
{
    dbg_cp2_printf("%s %s %s\n",
                   response_headers->status_line.http_version,
                   response_headers->status_line.status_code,
                   response_headers->status_line.reason_phrase);
    dbg_cp2_printf("cache_control: %s\n",
                   response_headers->general_header.cache_control);
    dbg_cp2_printf("connection: %s\n",
                   response_headers->general_header.connection);
    dbg_cp2_printf("date: %s\n",
                   response_headers->general_header.date);
    dbg_cp2_printf("paragma: %s\n",
                   response_headers->general_header.paragma);
    dbg_cp2_printf("transfer_encoding: %s\n",
                   response_headers->general_header.transfer_encoding);
    dbg_cp2_printf("server: %s\n",
                   response_headers->response_header.server);
    dbg_cp2_printf("allow: %s\n",
                   response_headers->entity_header.allow);
    dbg_cp2_printf("content_encoding: %s\n",
                   response_headers->entity_header.content_encoding);
    dbg_cp2_printf("content_language: %s\n",
                   response_headers->entity_header.content_language);
    dbg_cp2_printf("content_length: %ld\n",
                   response_headers->entity_header.content_length);
    dbg_cp2_printf("content_type: %s\n",
                   response_headers->entity_header.content_type);
    dbg_cp2_printf("last_modified: %s\n",
                   response_headers->entity_header.last_modified);
}