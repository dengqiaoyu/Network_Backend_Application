#include "lisod.h"
#include "log.h"
#include "pdef_type.h"
#include "dbg_func.h"


FILE *logfp = NULL;
int logfd = -1;
static param lisod_param;
// ./lisod 2090 7114 ../tmp/lisod.log ../tmp/lisod.lock ../tmp/www ../tmp/cgi/cgi_script.py ../tmp/grader.key ../tmp/grader.crt

int main(int argc, char **argv) {
    int listenfd, connfd;
    ssize_t ret;
    socklen_t client_len;
    struct sockaddr_storage client_addr;
    static pools pool;
    struct timeval tv_selt = {S_SELT_TIMEOUT, US_SELT_TIMEOUT};
    struct timeval tv_recv = {S_RECV_TIMEOUT, US_RECV_TIMEOUT};

    signal(SIGTSTP, sigtstp_handler);
    signal(SIGINT, sigtstp_handler);
    signal(SIGPIPE, SIG_IGN);

    dbg_cp2_printf("----- http1.1 Server -----\n");

    ret = check_argv(argc, argv, &lisod_param);
    if (ret < 0) {
        fprintf(logfp, "Argumens is not valid, server terminated.\n");
        return -1;
    }

    logfd = init_log(lisod_param.log, argc, argv);
    if (logfd < 0) {
        fprintf(logfp, "Log file initialnizing failed, server terminated.\n");
        return -1;
    }
    logfp = fdopen(logfd, "a");

    listenfd = open_listenfd(lisod_param.http_port);
    if (listenfd < 0) {
        fprintf(logfp, "Port listening failed, server terminated\n");
        return -1;
    }

    init_pool(listenfd, &pool);

    while (1) {
        pool.ready_set = pool.active_set;
        pool.num_ready = select(FD_SETSIZE, &pool.ready_set, NULL, NULL,
                                &tv_selt);

        if (FD_ISSET(listenfd, &pool.ready_set)) {
            client_len = sizeof(struct sockaddr_storage);
            connfd = accept(listenfd, (struct sockaddr *)&client_addr,
                            &client_len);
            // TODO Should we check for connfd for more than 1024?
            if (connfd < 0) {
                fprintf(logfp, "Failed accepting connection in main.\n");
                continue;
            }

            char c_host[MAXLINE], c_port[MAXLINE];
            int flags = NI_NUMERICHOST | NI_NUMERICSERV;
            ret = getnameinfo((struct sockaddr *)&client_addr, client_len,
                              c_host, MAXLINE, c_port, MAXLINE, flags);
            if (ret != 0) {
                fprintf(logfp, "Can not resolve client's IP or port in main.\n");
            }
            else {
                fprintf(logfp, "Accept connection from client %s:%s.\n",
                        c_host, c_port);
            }

            ret = setsockopt(connfd, SOL_SOCKET, SO_RCVTIMEO,
                             (char *)&tv_recv, sizeof(struct timeval));
            if (ret < 0)
            {
                fprintf(logfp, "Failed setting tv_recv in main.\n");
            }

            ret = add_client(connfd, &pool, c_host);
            if (ret < 0)
            {
                fprintf(logfp, "Client adding failed in main.\n");
            }
        }

        if (server_clients(&pool) < 0)
        {
            fprintf(logfp, "server_clients Failed.\n");
        }
        fflush(logfp);
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
    close_log(logfp);
    exit(1);
}

int check_argv(int argc, char **argv, param *lisod_param) {
    memset(lisod_param, 0, sizeof(lisod_param));
    if (argc < 9) {
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

    if (atoi(argv[1]) < 1024 || atoi(argv[1]) > 65535) {
        fprintf(stderr, "Usage: HTTP port should be between 1024 and 65535.\n");
        return -1;
    }
    else {
        strncpy(lisod_param->http_port, argv[1], MAXLINE);
    }

    if (atoi(argv[2]) < 1024 || atoi(argv[2]) > 65535) {
        fprintf(stderr, "Usage: HTTPs port should be between 1024 and 65535.\n");
        return -1;
    }
    else if (!strcmp(argv[1], argv[2])) {
        fprintf(stderr, "Usage: HTTPs port should not equal HTTP port.\n");
        return -1;
    }
    else {
        strncpy(lisod_param->https_port, argv[2], MAXLINE);
    }

    if (strlen(argv[3]) > MAXLINE) {
        fprintf(stderr, "Log file path too long.\n");
        return -1;
    }
    else {
        strncpy(lisod_param->log, argv[3], MAXLINE);
    }

    if (strlen(argv[4]) > MAXLINE) {
        fprintf(stderr, "Lock file path too long.\n");
        return -1;
    }
    else {
        strncpy(lisod_param->lock, argv[4], MAXLINE);
    }

    if (strlen(argv[5]) > MAXLINE) {
        fprintf(stderr, "WWW folder too long.\n");
        return -1;
    }
    else {
        strncpy(lisod_param->www, argv[5], MAXLINE);
    }

    if (strlen(argv[6]) > MAXLINE) {
        fprintf(stderr, "CGI script path too long.\n");
        return -1;
    }
    else {
        strncpy(lisod_param->cgi_scp, argv[6], MAXLINE);
    }

    if (strlen(argv[7]) > MAXLINE) {
        fprintf(stderr, "Private key file path too long.\n");
        return -1;
    }
    else {
        strncpy(lisod_param->priv_key, argv[7], MAXLINE);
    }

    if (strlen(argv[8]) > MAXLINE) {
        fprintf(stderr, "Certificated file path too long.\n");
        return -1;
    }
    else {
        strncpy(lisod_param->cert_file, argv[8], MAXLINE);
    }
    return 0;
}

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
        fprintf(logfp, "Failed getting address information in open_listenfd.\n");
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
                return -1;
            }
        }
    }

    freeaddrinfo(listp);
    if (!p) {
        fprintf(logfp, "No address worked in open_listenfd.\n");
        return -1;
    }

    ret = listen(listenfd, LISTENQ);
    if (ret < 0) {
        ret = close(listenfd);
        if (ret < 0) {
            fprintf(logfp, "Failed closing listening file descriptor ");
            fprintf(logfp, "in open_listenfd.\n");
            return -1;
        }
        fprintf(logfp, "Failed listening on socket.\n");
        return -1;
    }

    return listenfd;
}

void init_pool(int listenfd, pools *p) {
    size_t i;

    FD_ZERO(&p->active_set);
    FD_SET(listenfd, &p->active_set);
    for (i = 0; i < FD_SETSIZE; i++) {
        p->clientfd[i] = -1;
        p->ign_first[i] = -1;
        p->too_long[i] = -1;
        memset(p->cached_buf[i], 0, REQ_BUF_SIZE + 1);
        memset(p->clientip[i], 0, MAX_SIZE_S + 1);
    }
}

int add_client(int connfd, pools *p, char *c_host)
{
    int i;

    p->num_ready--;

    for (i = 6; i < FD_SETSIZE; i++)
    {
        if (p->clientfd[i] < 0)
        {
            p->clientfd[i] = connfd;
            p->ign_first[connfd] = 0;
            p->too_long[connfd] = 0;
            memset(p->cached_buf[connfd], 0, REQ_BUF_SIZE + 1);
            FD_SET(connfd, &p->active_set);
            strncpy(p->clientip[connfd], c_host, MAX_SIZE_S);

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
                    fprintf(logfp, "  Get %s %s request from %s.\n",
                            request_rover->http_method,
                            request_rover->http_uri,
                            p->clientip[connfd]);
                    fprintf(logfp, "    User-Agent: %s\n",
                            request_analyzed.user_agent);
                    print_request_analyzed(&request_analyzed);
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

    memset(request_analyzed, 0, sizeof(Request_analyzed));

    for (index = 0; index < request->header_count; index++)
    {
        ret = strncasecmp("connection", request->headers[index].header_name,
                          MAX_SIZE);
        if (!ret)
        {
            strncpy(request_analyzed->connection,
                    request->headers[index].header_value, MAX_SIZE_S);
            request_analyzed->connection[MAX_SIZE_S - 1] = 0;
        }

        ret = strncasecmp("accept-charset",
                          request->headers[index].header_name,
                          MAX_SIZE);
        if (!ret)
        {
            strncpy(request_analyzed->accept_charset,
                    request->headers[index].header_value, MAX_SIZE_S);
            request_analyzed->accept_charset[MAX_SIZE_S - 1] = 0;
        }

        ret = strncasecmp("accept-encoding", request->headers[index].header_name,
                          MAX_SIZE);
        if (!ret)
        {
            strncpy(request_analyzed->accept_encoding,
                    request->headers[index].header_value, MAX_SIZE_S);
            request_analyzed->accept_encoding[MAX_SIZE_S - 1] = 0;
        }

        ret = strncasecmp("accept-language", request->headers[index].header_name,
                          MAX_SIZE);
        if (!ret)
        {
            strncpy(request_analyzed->accept_language,
                    request->headers[index].header_value, MAX_SIZE_S);
            request_analyzed->accept_language[MAX_SIZE_S - 1] = 0;
        }

        ret = strncasecmp("host", request->headers[index].header_name,
                          MAX_SIZE);
        if (!ret)
        {
            strncpy(request_analyzed->host,
                    request->headers[index].header_value, MAX_SIZE_S);
            request_analyzed->host[MAX_SIZE_S - 1] = 0;
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
    contentfd = -1;


    if (!strncmp("HTTP/1.0", request->http_version, MAX_SIZE_S))
    {
        if_close_connnection = 1;
    }
    else if (!strncmp("HTTP/1.1", request->http_version, MAX_SIZE_S))
    {
        if_close_connnection = 0;
    }
    else
    {
        status_code = 505;
    }
    strncpy(response_headers.status_line.http_version, "HTTP/1.1",
            MAX_SIZE_S);
    strncpy(response_headers.general_header.cache_control, "no-cache",
            MAX_SIZE_S);
    if (!strncmp("close", request_analyzed->connection, MAX_SIZE_S))
    {
        strncpy(response_headers.general_header.connection, "close",
                MAX_SIZE_S);
        if_close_connnection = 1;
    }
    else
    {
        strncpy(response_headers.general_header.connection, "keep-alive",
                MAX_SIZE_S);
    }

    char *time_GMT = get_rfc1123_date();
    strncpy(response_headers.general_header.date, time_GMT,
            MAX_SIZE_S);
    free(time_GMT);
    strncpy(response_headers.general_header.paragma, "no-cache",
            MAX_SIZE_S);
    strncpy(response_headers.general_header.transfer_encoding, "identity",
            MAX_SIZE_S);
    strncpy(response_headers.response_header.server, "liso/1.0",
            MAX_SIZE_S);
    strncpy(response_headers.entity_header.allow, "GET, HEAD",
            MAX_SIZE_S);
    strncpy(response_headers.entity_header.content_encoding, "identity",
            MAX_SIZE_S);
    strncpy(response_headers.entity_header.content_language, "en",
            MAX_SIZE_S);
    //dbg_cp2_printf("line 591\n");
    //print_response_headers(&response_headers);

    status_code = check_http_method(request->http_method);

    if (status_code == 200)
    {
        if (!strncmp(request->http_method, "POST", MAX_SIZE_S))
        {
            response_headers.entity_header.content_length = 0;
            strncpy(response_headers.entity_header.content_type,
                    "\0", MAX_SIZE_S);
            strncpy(response_headers.entity_header.last_modified,
                    "\0", MAX_SIZE_S);
            snprintf(response_headers.status_line.status_code, MAX_SIZE_S,
                     "%d", status_code);
            strncpy(response_headers.status_line.reason_phrase,
                    "OK", MAX_SIZE_S);
        }
        else if (!strncmp(request->http_method, "GET", MAX_SIZE_S))
        {
            //dbg_cp2_printf("line 601\n");
            status_code = get_contentfd(request, &response_headers, &contentfd);
            //dbg_cp2_printf("status_code: %d\n", status_code);
            //dbg_cp2_printf("response_headers_text:[\n%s]\n", response_headers_text);
            //exit(1);
        }
        else
        {
            //dbg_cp2_printf("line 601\n");
            status_code = get_contentfd(request, &response_headers, &contentfd);
            //dbg_cp2_printf("status_code: %d\n", status_code);
            //dbg_cp2_printf("response_headers_text:[\n%s]\n", response_headers_text);
            //exit(1);
            contentfd = -1;
        }
    }

    if (status_code != 200)
    {
        get_error_content(status_code, response_content_text,
                          &response_headers);
        //dbg_cp2_printf("response_headers_text:[\n%s]\n", response_headers_text);
        //dbg_cp2_printf("response_content_text:[\n%s]\n", response_content_text);
        //dbg_cp2_printf("line 617\n");
        //exit(1);
    }
    //dbg_cp2_printf("status_code: %d\n", status_code);
    get_response_headers(response_headers_text, &response_headers);
    if (status_code == 200 && contentfd != -1)
    {
        dbg_cp2_printf("line 648\n");
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
    //dbg_cp2_printf("line 648\n");
    ret = write_to_socket(status_code, response_headers_text,
                          response_content_text, response_content_ptr,
                          response_headers.entity_header.content_length,
                          connfd);

    if (response_content_ptr != (void *)(-1) && (response_content_ptr != NULL))
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
    if (!strncmp("GET", http_method, MAX_SIZE_S))
    {
        status_code = 200;
    }
    else if (!strncmp("HEAD", http_method, MAX_SIZE_S))
    {
        status_code = 200;
    }
    else if (!strncmp("POST", http_method, MAX_SIZE_S))
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
    if (response_headers->entity_header.content_length != 0)
    {
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
    }
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
    snprintf(response_headers->status_line.status_code, MAX_SIZE_S, "%d",
             status_code);
    strncpy(response_headers->status_line.reason_phrase,
            shortmsg, MAX_SIZE_S);
    strncpy(response_headers->entity_header.content_type,
            "text/html", MAX_SIZE_S);

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
            MAX_SIZE_S);
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
    dbg_cp2_printf("line 797, http_uri: %s\n", request->http_uri);
    dbg_cp2_printf("line 798, status_code: %d\n", status_code);
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
        snprintf(path_home, MAX_SIZE, "%s%s\0", lisod_param.www,
                 "/home.html");
        dbg_cp2_printf("path_home: %s\n", path_home);
        snprintf(path_index, MAX_SIZE, "%s%s\0", lisod_param.www,
                 "/index.html");
        dbg_cp2_printf("path_index: %s\n", path_index);
        if (stat(path_home, &sbuf) == 0)
        {
            strncpy(request->http_uri, path_home, MAX_SIZE - 1);
        }
        else if (stat(path_index, &sbuf) == 0)
        {
            strncpy(request->http_uri, path_index, MAX_SIZE - 1);
        }
        snprintf(file_name, MAX_SIZE, "%s", request->http_uri);
    }
    else
    {
        //dbg_cp2_printf("line 826, file_name: %s\n", file_name);
        snprintf(file_name, MAX_SIZE, "%s%s\0", lisod_param.www,
                 request->http_uri);
    }
    dbg_cp2_printf("line 831, file_name: %s\n", file_name);
    if (stat(file_name, &sbuf) < 0)
    {
        dbg_cp2_printf("line 879\n");
        status_code = 404;
        *contentfd = -1;
        return status_code;
    }

    if (!(S_ISREG(sbuf.st_mode)) || !(S_IRUSR & sbuf.st_mode))
    {
        dbg_cp2_printf("line 907\n");
        status_code = 403;
        *contentfd = -1;
        return status_code;
    }
    //dbg_cp2_printf("line 845\n");
    if (!strncmp(request->http_method, "POST", MAX_SIZE_S))
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
                file_type, MAX_SIZE_S);
        *contentfd = open(file_name, O_RDONLY, 0);
        if (*contentfd == -1)
        {
            fprintf(logfp, "Failed opening file %s.\n", file_name);
            dbg_cp2_printf("line 929\n");
            status_code = 403;
            return status_code;
        }
        char *last_modified = NULL;
        last_modified = get_last_modified_date(&sbuf.st_mtime);
        snprintf(response_headers->entity_header.last_modified, MAX_SIZE_S, "%s",
                 last_modified);
        free(last_modified);
    }

    snprintf(response_headers->status_line.status_code, MAX_SIZE_S, "%d",
             status_code);
    strncpy(response_headers->status_line.reason_phrase,
            "OK", MAX_SIZE_S);

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

    if (response_content_ptr != NULL)
    {
        response_content = response_content_ptr;
    }
    else if (response_content_text[0] != 0)
    {
        response_content = response_content_text;
        content_size = strlen(response_content);
    }
    else
    {
        response_content = NULL;
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
    if (response_content == NULL)
    {
        return 0;
    }
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
    p->ign_first[connfd] = 0;
    p->too_long[connfd] = 0;
    memset(p->cached_buf[connfd], 0, REQ_BUF_SIZE + 1);
    memset(p->clientip[connfd], 0, MAX_SIZE_S);
    return 0;
}