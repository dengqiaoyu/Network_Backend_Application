#include "lisod.h"
#include "log.h"
#include "dbg_func.h"


static const char *FILE_SUFFIX[TYPE_SIZE] =
{ ".html", ".css", ".gif", ".png", ".jpg"};

static const char *FILE_TYPE[TYPE_SIZE] =
{ "text/html", "text/css", "image/gif", "image/png", "image/jpeg"};

FILE *logfp = NULL;
static int logfd = -1;
int errfd = -1;
int old_stdin;
int old_stdout;
int old_stderr;
SSL_CTX *ssl_context = NULL;
static param lisod_param;
// ./lisod 2090 7114 ../tmp/lisod.log ../tmp/lisod.lock ../tmp/www ../tmp/cgi/cgi_script.py ../tmp/grader.key ../tmp/grader.crt

int main(int argc, char **argv) {
    int listenfd, ssl_listenfd, connfd, ssl_connfd;
    ssize_t ret;
    socklen_t client_len;
    struct sockaddr_storage client_addr;
    static pools pool;
    struct timeval tv_selt = {S_SELT_TIMEOUT, US_SELT_TIMEOUT};
    mode_t m_error = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;

    dbg_cp2_printf("----- http1.1 Server -----\n");

    ret = check_argv(argc, argv, &lisod_param);
    if (ret < 0) {
        fprintf(stderr, "Argumens is not valid, server terminated.\n");
        return -1;
    }

    // ret = daemonize(lisod_param.lock);
    // if (ret < 0) {
    //     fprintf(stderr, "Daemonize failed, server terminated.\n");
    //     return -1;
    // }
    signal(SIGPIPE, SIG_IGN);
    signal(SIGTSTP, sigtstp_handler);
    signal(SIGINT, sigtstp_handler);

    logfd = init_log(lisod_param.log, argc, argv);
    errfd = open("./fd_reserved", O_WRONLY | O_CREAT, m_error);
    if (logfd < 0) {
        fprintf(stderr, "Log file initialnizing failed, server terminated.\n");
        return -1;
    }
    logfp = fdopen(logfd, "a");

    listenfd = open_listenfd(lisod_param.http_port);
    if (listenfd < 0) {
        fprintf(logfp, "Port listening failed, server terminated\n");
        fupdate(logfp);
        return -1;
    }

    ssl_listenfd = open_tls_listenfd(lisod_param.https_port,
                                     lisod_param.priv_key,
                                     lisod_param.cert_file);
    if (ret < 0) {
        fprintf(logfp, "SSL Port listening failed, server terminated\n");
        fupdate(logfp);
        return -1;
    }
    init_pool(listenfd, ssl_listenfd, &pool);

    while (1) {
        pool.ready_set = pool.active_set;
        pool.num_ready = select(FD_SETSIZE, &pool.ready_set, NULL, NULL,
                                &tv_selt);
        //dbg_cp3_printf("FD_ISSET(7, &p->ready_set): %d\n", FD_ISSET(7, &pool.ready_set));

        if (FD_ISSET(listenfd, &pool.ready_set)) {
            client_len = sizeof(struct sockaddr_storage);
            connfd = accept(listenfd, (struct sockaddr *)&client_addr,
                            &client_len);
            if (connfd < 0) {
                if (errno == EMFILE || errno == ENFILE) {
                    Close(errfd);
                    errfd = accept(listenfd, (struct sockaddr *)&client_addr,
                                   &client_len);
                    // TODO to be tested
                    ret = send_maxfderr(errfd);
                    Close(errfd);
                    errfd = open("./fd_reserved", O_WRONLY | O_CREAT,
                                 m_error);
                }
                else {
                    fprintf(logfp, "Failed accepting coonection in main\n");
                    fupdate(logfp);
                    continue;
                }
            }
            else {
                char c_host[MAXLINE], c_port[MAXLINE];
                int flags = NI_NUMERICHOST | NI_NUMERICSERV;
                ret = getnameinfo((struct sockaddr *)&client_addr, client_len,
                                  c_host, MAXLINE, c_port, MAXLINE, flags);
                if (ret != 0) {
                    fprintf(logfp, "Can not resolve client's IP ");
                    fprintf(logfp, "or port in main.\n");
                    fupdate(logfp);
                }
                else {
                    fprintf(logfp, "Accept connection from client %s:%s.\n",
                            c_host, c_port);
                    fupdate(logfp);
                }

                // ret = setsockopt(connfd, SOL_SOCKET, SO_RCVTIMEO,
                //                  (char *)&tv_recv, sizeof(struct timeval));
                if (ret < 0) {
                    fprintf(logfp, "Failed setting tv_recv in main.\n");
                    fupdate(logfp);
                }

                ret = add_client(connfd, &pool, c_host, 0);
                if (ret < 0) {
                    Close(connfd);
                    fprintf(logfp, "Client adding failed in main.\n");
                    fupdate(logfp);
                }
            }
        }
        if (FD_ISSET(ssl_listenfd, &pool.ready_set)) {
            client_len = sizeof(struct sockaddr_storage);
            ssl_connfd = accept(ssl_listenfd,
                                (struct sockaddr *)&client_addr,
                                &client_len);
            // TODO max_connection
            if (ssl_connfd < 0) {
                fprintf(logfp, "Failed accept connection for SSL.\n");
                fupdate(logfp);
            }
            else {
                char c_host[MAXLINE], c_port[MAXLINE];
                int flags = NI_NUMERICHOST | NI_NUMERICSERV;
                ret = getnameinfo((struct sockaddr *)&client_addr, client_len,
                                  c_host, MAXLINE, c_port, MAXLINE, flags);
                if (ret != 0) {
                    fprintf(logfp, "Can not resolve client's IP ");
                    fprintf(logfp, "or port in main for SSL.\n");
                    fupdate(logfp);
                }
                else {
                    fprintf(logfp, "Accept connection from client %s:%s.\n",
                            c_host, c_port);
                    fupdate(logfp);
                }

                ret = add_client(ssl_connfd, &pool, c_host, 1);
                if (ret < 0) {
                    fprintf(logfp, "Client adding failed in main.\n");
                    fupdate(logfp);
                }
            }

        }

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

void sigtstp_handler()
{
    close_log(logfp);
    close(errfd);
    exit(1);
}

int check_argv(int argc, char **argv, param *lisod_param) {
    memset(lisod_param, 0, sizeof(param));
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
        fupdate(stderr);
        return -1;
    }

    if (atoi(argv[1]) < 1024 || atoi(argv[1]) > 65535) {
        fprintf(stderr, "Usage: HTTP port should be between 1024 and 65535.\n");
        fupdate(stderr);
        return -1;
    }
    else {
        strncpy(lisod_param->http_port, argv[1], MAXLINE);
    }

    if (atoi(argv[2]) < 1024 || atoi(argv[2]) > 65535) {
        fprintf(stderr, "Usage: HTTPs port should be between 1024 and 65535.\n");
        fupdate(stderr);
        return -1;
    }
    else if (!strcmp(argv[1], argv[2])) {
        fprintf(stderr, "Usage: HTTPs port should not equal HTTP port.\n");
        fupdate(stderr);
        return -1;
    }
    else {
        strncpy(lisod_param->https_port, argv[2], MAXLINE);
    }

    if (strlen(argv[3]) > MAXLINE) {
        fprintf(stderr, "Log file path too long.\n");
        fupdate(stderr);
        return -1;
    }
    else {
        strncpy(lisod_param->log, argv[3], MAXLINE);
    }

    if (strlen(argv[4]) > MAXLINE) {
        fprintf(stderr, "Lock file path too long.\n");
        fupdate(stderr);
        return -1;
    }
    else {
        strncpy(lisod_param->lock, argv[4], MAXLINE);
    }
    if (strlen(argv[5]) > MAXLINE) {
        fprintf(stderr, "WWW folder too long.\n");
        fupdate(stderr);
        return -1;
    }
    else {
        if (!access(argv[5], F_OK)) {
            strncpy(lisod_param->www, argv[5], MAXLINE);
        }
        else {
            fprintf(stderr, "WWW folder dose not exist.\n");
            fupdate(stderr);
            return -1;
        }
    }
    if (strlen(argv[6]) > MAXLINE) {
        fprintf(stderr, "CGI script path too long.\n");
        fupdate(stderr);
        return -1;
    }
    else {
        if (!access(argv[6], F_OK)) {
            strncpy(lisod_param->cgi_scp, argv[6], MAXLINE);
        }
        else {
            fprintf(stderr, "CGI script dose not exist.\n");
            fupdate(stderr);
            return -1;
        }
    }
    if (strlen(argv[7]) > MAXLINE) {
        fprintf(stderr, "Private key file path too long.\n");
        fupdate(stderr);
        return -1;
    }
    else {
        if (!access(argv[7], F_OK)) {
            strncpy(lisod_param->priv_key, argv[7], MAXLINE);
        }
        else {
            fprintf(stderr, "Private key file dose not exist.\n");
            fupdate(stderr);
            return -1;
        }
    }
    if (strlen(argv[8]) > MAXLINE) {
        fprintf(stderr, "Certificated file path too long.\n");
        fupdate(stderr);
        return -1;
    }
    else {
        if (!access(argv[8], F_OK)) {
            strncpy(lisod_param->cert_file, argv[8], MAXLINE);
        }
        else {
            fprintf(stderr, "Private key file dose not exist.\n");
            fupdate(stderr);
            return -1;
        }
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

int open_tls_listenfd(char *tls_port, char *priv_key, char *cert_file) {
    struct addrinfo hints, *listp, *p;
    int ssl_listenfd, optval = 1;
    ssize_t ret;

    SSL_load_error_strings();
    SSL_library_init();

    ssl_context = SSL_CTX_new(TLSv1_server_method());
    if (ssl_context == NULL) {
        fprintf(logfp, " Failed creating SSL context.\n");
        return -1;
    }

    ret = SSL_CTX_use_PrivateKey_file(ssl_context, priv_key, SSL_FILETYPE_PEM);
    if (ret == 0) {
        SSL_CTX_free(ssl_context);
        fprintf(logfp, "Failed associating private key.\n");
        return -1;
    }

    ret = SSL_CTX_use_certificate_file(ssl_context, cert_file,
                                       SSL_FILETYPE_PEM);
    if (ret == 0) {
        SSL_CTX_free(ssl_context);
        fprintf(logfp, "Failed associating certificate.\n");
        return -1;
    }

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE | AI_ADDRCONFIG;
    hints.ai_flags |= AI_NUMERICSERV;

    ret = getaddrinfo(NULL, tls_port, &hints, &listp);
    if (ret != 0) {
        fprintf(logfp, "Failed getting address information in open_listefd.\n");
        fupdate(logfp);
        return -1;
    }

    for (p = listp; p != NULL; p = p->ai_next) {
        ssl_listenfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (ssl_listenfd < 0) {
            continue;
        }

        if (setsockopt(ssl_listenfd, SOL_SOCKET, SO_REUSEADDR,
                       (const void *)&optval, sizeof(int)) < 0) {
            continue;
        }
        if (bind(ssl_listenfd, p->ai_addr, p->ai_addrlen) == 0) {
            break;
        }
        else {
            if (close(ssl_listenfd) < 0)
            {
                SSL_CTX_free(ssl_context);
                fprintf(logfp, "Failed closing listening file descriptor in");
                fprintf(logfp, "open_ssl_listenfd.\n");
                fupdate(logfp);
                return -1;
            }
        }
    }

    freeaddrinfo(listp);
    if (!p) {
        SSL_CTX_free(ssl_context);
        fprintf(logfp, "No address worked in open_ssl_listenfd.\n");
        fupdate(logfp);
        return -1;
    }

    ret = listen(ssl_listenfd, LISTENQ);
    if (ret < 0) {
        ret = close(ssl_listenfd);
        if (ret < 0) {
            SSL_CTX_free(ssl_context);
            fprintf(logfp, "Failed closing listening file descriptor ");
            fprintf(logfp, "in open_ssl_listenfd.\n");
            fupdate(logfp);
            return -1;
        }
        SSL_CTX_free(ssl_context);
        fprintf(logfp, "Failed listening on socket.\n");
        fupdate(logfp);
        return -1;
    }

    return ssl_listenfd;
}

void init_pool(int listenfd, int ssl_listenfd, pools *p) {
    size_t i;

    FD_ZERO(&p->active_set);
    FD_SET(listenfd, &p->active_set);
    FD_SET(ssl_listenfd, &p->active_set);
    for (i = 0; i < FD_SETSIZE; i++) {
        p->clientfd[i] = -1;
        p->SSL_client_ctx[i] = NULL;
        p->ign_first[i] = 0;
        p->too_long[i] = 0;
        p->close_fin[i] = 0;
        p->remain_req[i] = 0;
        memset(p->cached_buf[i], 0, REQ_BUF_SIZE + 1);
        p->cached_req[i] = NULL;
        memset(p->clientip[i], 0, MAX_SIZE_S + 1);
    }
}

ssize_t add_client(int connfd, pools *p, char *c_host, ssize_t if_ssl)
{
    ssize_t ret;
    p->num_ready--;
    if (if_ssl == 1) {
        SSL *client_context;
        client_context = SSL_new(ssl_context);
        if (client_context == NULL) {
            close(connfd);
            fprintf(logfp, "Failed creating client SSL context.\n");
            fupdate(logfp);
            return -1;
        }

        ret = SSL_set_fd(client_context, connfd);
        if (ret == 0) {
            close(connfd);
            SSL_free(client_context);
            fprintf(logfp, "Failed creating client SSL context.\n");
            fupdate(logfp);
            return -1;
        }

        ret = SSL_accept(client_context);
        if (ret <= 0) {
            close(connfd);
            SSL_free(client_context);
            fprintf(logfp, "Failed accepting client SSL context.\n");
            // fprintf(logfp, "%d\n", SSL_get_error(client_context, ret));
            // fprintf(logfp, "%d\n", SSL_ERROR_NONE);
            // fprintf(logfp, "%d\n", SSL_ERROR_ZERO_RETURN);
            // fprintf(logfp, "%d\n", SSL_ERROR_WANT_READ);
            // fprintf(logfp, "%d\n", SSL_ERROR_WANT_WRITE);
            // fprintf(logfp, "%d\n", SSL_ERROR_WANT_CONNECT);
            // fprintf(logfp, "%d\n", SSL_ERROR_WANT_ACCEPT);
            // fprintf(logfp, "%d\n", SSL_ERROR_WANT_X509_LOOKUP);
            // fprintf(logfp, "%d\n", SSL_ERROR_SYSCALL);
            // fprintf(logfp, "%d\n", SSL_ERROR_SSL);
            fupdate(logfp);
            return -1;
        }
        p->SSL_client_ctx[connfd] = client_context;
    }
    fcntl(connfd, F_SETFL, O_NONBLOCK);
    p->clientfd[connfd] = 1;
    p->ign_first[connfd] = 0;
    p->too_long[connfd] = 0;
    p->close_fin[connfd] = 0;
    p->remain_req[connfd] = 0;
    memset(p->cached_buf[connfd], 0, REQ_BUF_SIZE + 1);
    FD_SET(connfd, &p->active_set);
    strncpy(p->clientip[connfd], c_host, MAX_SIZE_S);
    return 0;
}

ssize_t serve_clients(pools *p) {
    size_t i, iter_count;
    ssize_t read_ret, ret;
    char skt_read_buf[SKT_READ_BUF_SIZE + 1] = {65};
    iter_count = 0;

    //TODO check start
    for (i = 0; (i < FD_SETSIZE) && (p->num_ready > 0); i++) {
        dbg_cp3_printf("connfd: %ld, status: %d\n", i, p->clientfd[i]);
        if ((p->clientfd[i] == 1) && (FD_ISSET(i, &p->ready_set))) {
            int connfd = i;
            size_t if_conn_close = 0;
            size_t read_offset = 0;
            SSL *client_context = p->SSL_client_ctx[i];
            p->num_ready--;

            if (client_context != NULL) {
                read_ret = SSL_read(client_context, skt_read_buf,
                                    SKT_READ_BUF_SIZE);
            }
            else {
                dbg_cp3_printf("line 562, should go to here\n");
                read_ret = read(connfd, skt_read_buf, SKT_READ_BUF_SIZE);
            }
            dbg_cp3_printf("line 564\n");
            while (read_ret >= 0 && iter_count < MAX_READ_ITER_COUNT) {
                dbg_cp3_printf("iter_count: %ld\n", iter_count);
                dbg_cp3_printf("read_ret: %ld\n", read_ret);
                if (read_ret == 0) {
                    Close_conn(connfd, p);
                    if_conn_close = 1;
                    break;
                }
                iter_count++;
                read_offset = read_offset + read_ret;
                if (read_offset == SKT_READ_BUF_SIZE) {
                    break;
                }
                if (client_context != NULL) {
                    read_ret = SSL_read(client_context,
                                        &skt_read_buf[read_offset],
                                        SKT_READ_BUF_SIZE - read_offset);
                }
                else {
                    read_ret = read(connfd, &skt_read_buf[read_offset],
                                    SKT_READ_BUF_SIZE - read_offset);
                }
                dbg_cp3_printf("after read_ret: %ld errno: %d\n", read_ret, errno);
            }
            if (read_ret < 0) {
                if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    Close_conn(connfd, p);
                    if_conn_close = 1;
                }
            }
            if (if_conn_close == 1) {
                continue;
            }

            dbg_cp3_printf("$$$$$$$$$$$$$$$$$$$$$$$$$$$$\n");
            dbg_cp3_printf("skt_read_buf in lisod.c:\n%s\n",
                           skt_read_buf);
            dbg_cp3_printf("$$$$$$$$$$$$$$$$$$$$$$$$$$$$\n");
            Requests *reqs = parse(skt_read_buf, read_ret, connfd, p);
            Requests *req_rover = reqs;
            print_request(req_rover);
            req_rover = reqs;
            while (req_rover != NULL) {
                ret = search_first_position(req_rover->http_uri,
                                            SCRIPT_NAME);
                size_t status_code = 200;
                if (ret != 0) {
                    Request_analyzed req_anlzed;
                    memset(&req_anlzed, 0, sizeof(Request_analyzed));
                    get_request_analyzed(&req_anlzed, req_rover);
                    fprintf(logfp, "  Get %s %s request from %s.\n",
                            req_rover->http_method,
                            req_rover->http_uri,
                            p->clientip[connfd]);
                    fprintf(logfp, "    User-Agent: %s\n",
                            req_anlzed.user_agent);
                    fupdate(logfp);
                    print_request_analyzed(&req_anlzed);
                    status_code = serve_static(&req_anlzed, req_rover, p,
                                               connfd, client_context);
                }
                else {
                    Request_analyzed req_anlzed;
                    memset(&req_anlzed, 0, sizeof(Request_analyzed));
                    get_request_analyzed(&req_anlzed, req_rover);
                    fprintf(logfp, "  Get %s %s request from %s.\n",
                            req_rover->http_method,
                            req_rover->http_uri,
                            p->clientip[connfd]);
                    fprintf(logfp, "    User-Agent: %s\n",
                            req_anlzed.user_agent);
                    fupdate(logfp);
                    status_code = serve_dynamic(&req_anlzed, req_rover, p,
                                                connfd, client_context, -1);
                    int child_stat = 0;
                    pid_t child_pid = waitpid(-1, &child_stat, WNOHANG);
                    if (child_pid != 0) {
                        dbg_cp3_printf("child %d terminated with %d\n",
                                       child_pid, child_stat);
                    }
                }
                if (status_code != 200) {
                    ret = send_error(connfd, client_context, status_code);
                    if (ret < 0) {
                        Close_conn(connfd, p);
                        break;
                    }
                }
                else if (status_code < 0) {
                    Close_conn(connfd, p);
                    break;
                }
                req_rover = req_rover->next_req;
            }
            destory_requests(reqs);
            reqs = NULL;
        }
        else if ((p->clientfd[i] > 1) && (FD_ISSET(i, &p->ready_set))) {
            int cgi_rspfd = i;
            int connfd = p->clientfd[i];
            dbg_cp3_printf("cgi_rspfd: %d, connfd: %d\n", cgi_rspfd, connfd);
            SSL *client_context = p->SSL_client_ctx[connfd];
            p->num_ready--;
            if (p->clientfd[connfd] == -1) {
                fprintf(logfp, "failed, CGI client have close connection\n");
                Close_conn(cgi_rspfd, p);
                continue;
            }
            ret = serve_dynamic(NULL, NULL, p, connfd, client_context,
                                cgi_rspfd);
            if (ret < 0) {
                Close_conn(connfd, p);
            }
            int child_stat = 0;
            pid_t child_pid = waitpid(-1, &child_stat, WNOHANG);
            if (child_pid != 0) {
                dbg_cp3_printf("child %d terminated with %d\n",
                               child_pid, child_stat);
            }
        }
    }
    return 0;
}

void get_request_analyzed(Request_analyzed *req_anlzed,
                          Requests *req)
{
    int index = 0;
    int ret = 0;

    memset(req_anlzed, 0, sizeof(Request_analyzed));

    for (index = 0; index < req->h_count; index++)
    {
        ret = strncasecmp("connection", req->headers[index].h_name,
                          MAX_SIZE);
        if (!ret)
        {
            strncpy(req_anlzed->connection,
                    req->headers[index].h_value, MAX_SIZE_S);
            req_anlzed->connection[MAX_SIZE_S - 1] = 0;
        }

        ret = strncasecmp("accept-charset",
                          req->headers[index].h_name,
                          MAX_SIZE);
        if (!ret)
        {
            strncpy(req_anlzed->accept_charset,
                    req->headers[index].h_value, MAX_SIZE_S);
            req_anlzed->accept_charset[MAX_SIZE_S - 1] = 0;
        }

        ret = strncasecmp("accept-encoding", req->headers[index].h_name,
                          MAX_SIZE);
        if (!ret)
        {
            strncpy(req_anlzed->accept_encoding,
                    req->headers[index].h_value, MAX_SIZE_S);
            req_anlzed->accept_encoding[MAX_SIZE_S - 1] = 0;
        }

        ret = strncasecmp("accept-language", req->headers[index].h_name,
                          MAX_SIZE);
        if (!ret)
        {
            strncpy(req_anlzed->accept_language,
                    req->headers[index].h_value, MAX_SIZE_S);
            req_anlzed->accept_language[MAX_SIZE_S - 1] = 0;
        }

        ret = strncasecmp("host", req->headers[index].h_name,
                          MAX_SIZE);
        if (!ret)
        {
            strncpy(req_anlzed->host,
                    req->headers[index].h_value, MAX_SIZE_S);
            req_anlzed->host[MAX_SIZE_S - 1] = 0;
        }

        ret = strncasecmp("user-agent", req->headers[index].h_name,
                          MAX_SIZE);
        if (!ret)
        {
            strncpy(req_anlzed->user_agent,
                    req->headers[index].h_value, MAX_SIZE);
            req_anlzed->user_agent[MAX_SIZE - 1] = 0;
        }
    }
}

ssize_t serve_static(Request_analyzed *req_anlzed, Requests *req, pools *p,
                     int connfd, SSL *client_context)
{
    int status_code;
    Response_headers resp_hds;
    char resp_hds_text[MAX_TEXT + 1];
    char resp_ct_text[MAX_TEXT + 1];
    int contentfd, ret;
    size_t ct_size;
    char *resp_ct_ptr = NULL;
    memset(&resp_hds, 0, sizeof(Response_headers));
    memset(resp_hds_text, 0, MAX_TEXT + 1);
    memset(resp_ct_text, 0, MAX_TEXT + 1);
    contentfd = -1;

    status_code = req->error;
    if (status_code != 200) {
        return status_code;
    }

    if (!strncmp("HTTP/1.0", req->http_version, MAX_SIZE_S))
    {
        p->close_fin[connfd] = 1;
    }
    else if (!strncmp("HTTP/1.1", req->http_version, MAX_SIZE_S))
    {
        p->close_fin[connfd] = 0;
    }
    else
    {
        status_code = 505;
        return status_code;
    }
    strncpy(resp_hds.status_line.http_version, "HTTP/1.1",
            MAX_SIZE_S);
    strncpy(resp_hds.general_header.cache_control, "no-cache",
            MAX_SIZE_S);
    if (!strncmp("close", req_anlzed->connection, MAX_SIZE_S))
    {
        strncpy(resp_hds.general_header.connection, "close",
                MAX_SIZE_S);
        p->close_fin[connfd] = 1;
    }
    else
    {
        strncpy(resp_hds.general_header.connection, "keep-alive",
                MAX_SIZE_S);
    }


    char *time_GMT = get_rfc1123_date();
    strncpy(resp_hds.general_header.date, time_GMT,
            MAX_SIZE_S);
    free(time_GMT);
    strncpy(resp_hds.general_header.paragma, "no-cache",
            MAX_SIZE_S);
    strncpy(resp_hds.general_header.transfer_encoding, "identity",
            MAX_SIZE_S);
    strncpy(resp_hds.response_header.server, "liso/1.0",
            MAX_SIZE_S);
    strncpy(resp_hds.entity_header.allow, "GET, HEAD, POST",
            MAX_SIZE_S);
    strncpy(resp_hds.entity_header.content_encoding, "identity",
            MAX_SIZE_S);
    strncpy(resp_hds.entity_header.content_language, "en",
            MAX_SIZE_S);
    print_response_headers(&resp_hds);

    status_code = check_http_method(req->http_method);
    if (status_code != 200) {
        return status_code;
    }

    if (!strncmp(req->http_method, "POST", MAX_SIZE_S))
    {
        status_code = 501;
        return status_code;
    }
    else if (!strncmp(req->http_method, "GET", MAX_SIZE_S))
    {
        status_code = get_contentfd(req, &resp_hds, &contentfd);
        if (status_code != 200) {
            return status_code;
        }
    }
    else if (!strncmp(req->http_method, "HEAD", MAX_SIZE_S))
    {
        status_code = get_contentfd(req, &resp_hds, &contentfd);
        if (status_code != 200) {
            return status_code;
        }
        Close(contentfd);
        contentfd = -1;
    }

    get_response_headers(resp_hds_text, &resp_hds);
    if (contentfd != -1)
    {
        ct_size = resp_hds.entity_header.content_length;
        resp_ct_ptr = mmap(0, ct_size, PROT_READ, MAP_PRIVATE,
                           contentfd, 0);
        if (resp_ct_ptr == (void *)(-1))
        {
            fprintf(logfp, "Failed mapping request file.\n");
            fupdate(logfp);
            status_code = 500;
            return status_code;
        }
        Close(contentfd);
    }
    ret = write_to_socket(connfd, client_context, resp_hds_text,
                          resp_ct_text, resp_ct_ptr,
                          resp_hds.entity_header.content_length);
    if (ret < 0) {
        return -1;
    }
    if (resp_ct_ptr != (void *)(-1) && (resp_ct_ptr != NULL))
    {
        ret = munmap(resp_ct_ptr, ct_size);
        if (ret == -1)
        {
            fprintf(logfp, "Failed unmapping request file.\n");
            fupdate(logfp);
        }
    }

    if (p->close_fin[connfd] == 1 && p->remain_req[connfd] == 0) {
        Close_conn(connfd, p);
        dbg_cp3_printf("Closed!\n");
    }
    return 200;
}

ssize_t serve_dynamic(Request_analyzed *req_anlzed, Requests *req, pools *p,
                      int connfd, SSL * client_context, int cgi_rspfd) {
    ssize_t ret = 0;
    if (req != NULL) {
        int status_code;
        pid_t pid;
        int stdin_pipe[2];
        int stdout_pipe[2];

        status_code = check_http_method(req->http_method);
        if (status_code != 200) {
            return status_code;
        }

        status_code = req->error;
        if (status_code != 200) {
            return status_code;
        }

        if (pipe(stdin_pipe) < 0) {
            fprintf(logfp, "Failed piping for stdin.\n");
            fupdate(logfp);
            status_code = 500;
            return status_code;
        }
        if (pipe(stdout_pipe) < 0 ) {
            fprintf(logfp, "Failed piping for stdout.\n");
            fupdate(logfp);
            status_code = 500;
            return status_code;
        }

        pid = fork();
        if (pid < 0) {
            fprintf(logfp, "Failed forking child process.\n");
            status_code = 500;
            return status_code;
        }
        else if (pid == 0) {
            dbg_cp3_printf("entering child\n");
            Close(stdout_pipe[0]);
            Close(stdin_pipe[1]);
            ret = dup2(stdin_pipe[0], fileno(stdin));
            if (ret < 0) {
                fprintf(logfp, "Failed redirecting pipe to stdin of child.\n");
                // TODO error_handling in child
            }
            ret = dup2(stdout_pipe[1], fileno(stdout));
            if (ret < 0) {
                fprintf(logfp, "Failed redirecting pipe to stdout of child.\n");
                // TODO error_handling in child
            }
            dbg_cp3_fprintf(stderr, "line 935\n");
            char *ENVP[ENVP_len + 1];
            size_t i = 0;
            for (i = 0; i < ENVP_len; i++) {
                ENVP[i] = (char *) malloc((2 * MAX_SIZE + 1) + 1);
                if (ENVP[i] == NULL) {
                    fprintf(logfp, "Failed allocating memory for ENVP.\n");
                    // TODO error_handling in child
                }
                memset(ENVP[i], 0, (2 * MAX_SIZE + 1) + 1);
            }
            dbg_cp3_fprintf(stderr, "line 946\n");
            ENVP[ENVP_len] = NULL;
            if (p->SSL_client_ctx == NULL) {
                get_envp(p, connfd, req, ENVP, lisod_param.http_port);
            }
            else {
                get_envp(p, connfd, req, ENVP, lisod_param.https_port);
            }

            char *ARGV[2];
            ARGV[0] = (char *) malloc(MAXLINE + 1);
            memset(ARGV[0], 0, MAXLINE + 1);
            strncpy(ARGV[0], lisod_param.cgi_scp, MAXLINE);
            ARGV[1] = NULL;
            // TODO free envp
            // int ii = 0;
            // for (ii = 0; ii < ENVP_len; ii++) {
            //     dbg_cp3_fprintf(stderr, "%s\n", ENVP[ii]);
            // }
            dbg_cp3_fprintf(stderr, "line 954\n");
            ret = execve(ARGV[0], ARGV, ENVP);
            dbg_cp3_fprintf(stderr, "ret: %ld", ret);
            if (ret) {
                execve_error_handler();
                fprintf(logfp, "Failed executing execve syscall.\n");
                // TODO error_handling in child
            }
        }
        else if (pid > 0) {

            Close(stdout_pipe[1]);
            Close(stdin_pipe[0]);
            fcntl(stdout_pipe[0], F_SETFL, O_NONBLOCK);
            dbg_cp3_fprintf(stderr, "line 976\n");
            if (req->entity_len != 0) {
                ret = write(stdin_pipe[1], req->entity_body, req->entity_len);
                if (ret < 0) {
                    fprintf(logfp, "Failed writing to spawned CGI program.\n");
                    status_code = 500;
                    Close(stdin_pipe[1]);
                    return status_code;
                }
            }
            Close(stdin_pipe[1]);
            if (!strncmp("close", req_anlzed->connection, MAX_SIZE_S)) {
                p->close_fin[connfd] = 1;
            }
            add_cgi_rspfd(stdout_pipe[0], connfd, p);
            char cgi_buf[MAX_CGI_MSG + 1] = {0};
            size_t iter_count = 0;
            ssize_t read_ret = read(stdout_pipe[0], cgi_buf, MAX_CGI_MSG);
            dbg_cp3_fprintf(stderr, "line 994 read_ret: %ld, errno:  %d\n", read_ret, errno);
            dbg_cp3_fprintf(stderr, "line 994 stdout_pipe[0]: %d\n", stdout_pipe[0]);
            while (read_ret >= 0 && iter_count < MAX_CGI_ITER_COUNT) {
                if (read_ret > 0) {
                    dbg_cp3_printf("cgi_buf:\n %s\n", cgi_buf);
                    ret = write_to_socket(connfd, p->SSL_client_ctx[connfd],
                                          cgi_buf, NULL, NULL, 0);
                    // char header_temp[8192] = "HTTP/1.1 OK 200\r\nContent-Length: 700\r\n\r\n";
                    // ret = write_to_socket(connfd, p->SSL_client_ctx[connfd],
                    //                       header_temp, cgi_buf, NULL, 0);
                    if (ret < 0) {
                        fprintf(logfp,
                                "Failed sending CGI response to client.\n");
                        return -1;
                    }
                }
                else if (read_ret == 0) {
                    Close_conn(stdout_pipe[0], p);
                    if (p->close_fin[connfd] == 1 && p->remain_req[connfd] == 0)
                    {
                        dbg_cp3_printf("fd %d Connection_close is made\n", connfd);
                        Close_conn(connfd, p);
                    }
                    break;
                }
                iter_count++;
                memset(cgi_buf, 0, MAX_CGI_MSG + 1);
                read_ret = read(stdout_pipe[0], cgi_buf, MAX_CGI_MSG);
            }
            if (read_ret < 0) {
                if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    fprintf(logfp,
                            "Failed receiving message from CGI program.\n");
                    if (iter_count == 0) {
                        status_code = 500;
                        return status_code;
                    }
                    else {
                        return -1;
                    }
                }
            }
            p->remain_req[connfd]++;
        }
    }
    else {
        dbg_cp3_printf("cgi ready\n");
        char cgi_buf[MAX_CGI_MSG + 1] = {0};
        size_t iter_count = 0;
        ssize_t read_ret = read(cgi_rspfd, cgi_buf, MAX_CGI_MSG);
        dbg_cp3_printf("line 1028: read_ret: %ld\n", read_ret);
        dbg_cp3_printf("line 1044: errno: %d\n", errno);
        dbg_cp3_printf("line 1037: cgi_rspfd: %s\n", cgi_buf);
        while (read_ret >= 0 && iter_count < MAX_CGI_ITER_COUNT) {
            if (read_ret > 0) {
                ret = write_to_socket(connfd, p->SSL_client_ctx[connfd],
                                      cgi_buf, NULL, NULL, 0);
                // char header_temp[8192] = "HTTP/1.1 OK 200\r\nContent-Length: 700\r\n\r\n";
                // ret = write_to_socket(connfd, p->SSL_client_ctx[connfd],
                //                       header_temp, cgi_buf, NULL, 0);
                if (ret < 0) {
                    p->remain_req[connfd]--;
                    fprintf(logfp,
                            "Failed sending CGI response to client.\n");
                    return -1;
                }
            }
            else if (read_ret == 0) {
                p->remain_req[connfd]--;
                Close_conn(cgi_rspfd, p);
                dbg_cp3_printf("remain_req: %ld, close_fin: %ld\n",
                               p->remain_req[connfd],
                               p->close_fin[connfd]);
                if (p->close_fin[connfd] == 1 && p->remain_req[connfd] == 0)
                {
                    dbg_cp3_printf("line 1082 fd %d Connection_close is made\n", connfd);
                    Close_conn(connfd, p);
                }
                break;
            }
            iter_count++;
            read_ret = read(cgi_rspfd, cgi_buf, MAX_CGI_MSG);
            dbg_cp3_printf("after read_ret, read_ret: %ld\n", read_ret);
        }
        if (read_ret < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                p->remain_req[connfd]--;
                fprintf(logfp,
                        "Failed receiving message from CGI program.\n");
                return -1;
            }
        }
    }
    return 200;
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

void get_response_headers(char *resp_hds_text,
                          Response_headers *resp_hds)
{
    char text_tmp[MAX_TEXT] = {0};
    size_t text_len = 0;
    snprintf(text_tmp, MAX_TEXT, "%s %s %s\r\n",
             resp_hds->status_line.http_version,
             resp_hds->status_line.status_code,
             resp_hds->status_line.reason_phrase);
    strncat(resp_hds_text, text_tmp,
            MAX_TEXT - text_len);
    text_len +=  strlen(text_tmp);
    snprintf(text_tmp, MAX_TEXT, "Cache-Control: %s\r\n",
             resp_hds->general_header.cache_control);
    strncat(resp_hds_text, text_tmp,
            MAX_TEXT - text_len);
    text_len +=  strlen(text_tmp);
    snprintf(text_tmp, MAX_TEXT, "Connection: %s\r\n",
             resp_hds->general_header.connection);
    strncat(resp_hds_text, text_tmp,
            MAX_TEXT - text_len);
    text_len +=  strlen(text_tmp);
    snprintf(text_tmp, MAX_TEXT, "Date: %s\r\n",
             resp_hds->general_header.date);
    strncat(resp_hds_text, text_tmp,
            MAX_TEXT - text_len);
    text_len +=  strlen(text_tmp);
    snprintf(text_tmp, MAX_TEXT, "Paragma: %s\r\n",
             resp_hds->general_header.paragma);
    strncat(resp_hds_text, text_tmp,
            MAX_TEXT - text_len);
    text_len +=  strlen(text_tmp);
    snprintf(text_tmp, MAX_TEXT, "Transfer-Encoding: %s\r\n",
             resp_hds->general_header.transfer_encoding);
    strncat(resp_hds_text, text_tmp,
            MAX_TEXT - text_len);
    text_len +=  strlen(text_tmp);
    snprintf(text_tmp, MAX_TEXT, "Server: %s\r\n",
             resp_hds->response_header.server);
    strncat(resp_hds_text, text_tmp,
            MAX_TEXT - text_len);
    text_len +=  strlen(text_tmp);
    snprintf(text_tmp, MAX_TEXT, "Allow: %s\r\n",
             resp_hds->entity_header.allow);
    strncat(resp_hds_text, text_tmp,
            MAX_TEXT - text_len);
    text_len +=  strlen(text_tmp);
    if (resp_hds->entity_header.content_length != 0)
    {
        snprintf(text_tmp, MAX_TEXT, "Content-Encoding: %s\r\n",
                 resp_hds->entity_header.content_encoding);
        strncat(resp_hds_text, text_tmp,
                MAX_TEXT - text_len);
        text_len +=  strlen(text_tmp);
        snprintf(text_tmp, MAX_TEXT, "Content-Language: %s\r\n",
                 resp_hds->entity_header.content_language);
        strncat(resp_hds_text, text_tmp,
                MAX_TEXT - text_len);
        text_len +=  strlen(text_tmp);
        snprintf(text_tmp, MAX_TEXT, "Content-Length: %ld\r\n",
                 resp_hds->entity_header.content_length);
        strncat(resp_hds_text, text_tmp,
                MAX_TEXT - text_len);
        text_len +=  strlen(text_tmp);
        snprintf(text_tmp, MAX_TEXT, "Content-Type: %s\r\n",
                 resp_hds->entity_header.content_type);
        strncat(resp_hds_text, text_tmp,
                MAX_TEXT - text_len);
        text_len +=  strlen(text_tmp);
        snprintf(text_tmp, MAX_TEXT, "Last-Modified: %s\r\n",
                 resp_hds->entity_header.last_modified);
        strncat(resp_hds_text, text_tmp,
                MAX_TEXT - text_len);
        text_len +=  strlen(text_tmp);
    }
    strncat(resp_hds_text, "\r\n", MAX_TEXT - text_len);
}

void get_error_content(int status_code, char *body,
                       Response_headers *resp_hds)
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
    case 414:
        strncpy(shortmsg, "Request-URI Too Large", MAX_TEXT);
        strncpy(cause, "The server is refusing to service the request because the Request-URI is longer than the server is willing tointerpret.",
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
    default:
        strncpy(shortmsg, "Unknown Error", MAX_TEXT);
        strncpy(cause, "I have no idea either.", MAX_TEXT);
        break;
    }
    snprintf(resp_hds->status_line.status_code, MAX_SIZE_S, "%d",
             status_code);
    strncpy(resp_hds->status_line.reason_phrase,
            shortmsg, MAX_SIZE_S);
    strncpy(resp_hds->entity_header.content_type,
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
    strncpy(resp_hds->entity_header.last_modified, time_GMT,
            MAX_SIZE_S);
    free(time_GMT);
    resp_hds->entity_header.content_length = strlen(body);
}

int get_contentfd(Requests *request, Response_headers *resp_hds,
                  int *contentfd)
{
    int status_code = 0;
    char file_name[MAX_SIZE + 1];
    char file_type[MAX_SIZE + 1];
    struct stat sbuf;
    memset(file_name, 0, MAX_SIZE + 1);
    memset(file_type, 0, MAX_SIZE + 1);
    strncpy(file_name, request->http_uri, MAX_SIZE);

    status_code = decode_asc(request->http_uri);

    dbg_cp2_printf("line 771\n");
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
        char path_home[MAX_SIZE + 1] = {0};
        char path_index[MAX_SIZE + 1] = {0};
        snprintf(path_home, MAX_SIZE, "%s%s", lisod_param.www,
                 "/home.html");
        dbg_cp2_printf("path_home: %s\n", path_home);
        snprintf(path_index, MAX_SIZE, "%s%s", lisod_param.www,
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
        snprintf(file_name, MAX_SIZE, "%s%s", lisod_param.www,
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
        resp_hds->entity_header.content_length = sbuf.st_size;
        strncpy(resp_hds->entity_header.content_type,
                file_type, MAX_SIZE_S);
        *contentfd = open(file_name, O_RDONLY, 0);
        if (*contentfd == -1)
        {
            fprintf(logfp, "Failed opening file %s.\n", file_name);
            fupdate(logfp);
            dbg_cp2_printf("line 929\n");
            status_code = 403;
            return status_code;
        }
        char *last_modified = NULL;
        last_modified = get_last_modified_date(&sbuf.st_mtime);
        snprintf(resp_hds->entity_header.last_modified, MAX_SIZE_S, "%s",
                 last_modified);
        free(last_modified);
    }

    snprintf(resp_hds->status_line.status_code, MAX_SIZE_S, "%d",
             status_code);
    strncpy(resp_hds->status_line.reason_phrase,
            "OK", MAX_SIZE_S);

    //print_response_headers(resp_hds);
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

ssize_t write_to_socket(int connfd, SSL *client_context, char *resp_hds_text,
                        char *resp_ct_text, char *resp_ct_ptr, size_t ct_size)
{
    char *response_content = NULL;
    size_t write_offset = 0;
    size_t headers_size = strlen(resp_hds_text);
    dbg_cp3_printf("resp_hds_text: %s\n", resp_hds_text);
    //dbg_cp3_printf("headers_size: %ld\n", headers_size);
    if (resp_ct_ptr != NULL)
    {
        response_content = resp_ct_ptr;
    }
    else if (resp_ct_text != NULL && resp_ct_text[0] != 0)
    {
        response_content = resp_ct_text;
        ct_size = strlen(response_content);
    }
    else
    {
        response_content = NULL;
    }

    dbg_cp3_printf("response_content:\n%s\n", response_content);
    while (1)
    {
        ssize_t write_ret = 0;
        if (client_context != NULL) {
            write_ret = SSL_write(client_context, resp_hds_text + write_offset,
                                  headers_size);
            dbg_cp2_printf("write_ret: %ld\n", write_ret);
            dbg_cp2_printf("SSL_get_error: %d\n", SSL_get_error(client_context, write_ret));
        }
        else {
            write_ret = send(connfd, resp_hds_text + write_offset,
                             headers_size, MSG_WAITALL);
        }

        //dbg_cp2_printf("write_ret: %d\n", write_ret);
        if (write_ret < 0)
        {
            fprintf(logfp, "Failed writing headers to socket on %d.\n",
                    connfd);
            fupdate(logfp);
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
    if (response_content == NULL)
    {
        return 0;
    }
    write_offset = 0;
    while (1)
    {
        ssize_t write_ret = 0;
        if (client_context != NULL) {
            write_ret = SSL_write(client_context, response_content + write_offset,
                                  ct_size);
            dbg_cp2_printf("write_ret: %ld\n", write_ret);
            dbg_cp2_printf("SSL_get_error: %d\n", SSL_get_error(client_context, write_ret));
        }
        else {
            write_ret = send(connfd, response_content + write_offset,
                             ct_size, MSG_WAITALL);
        }
        //dbg_cp2_printf("write_ret: %d\n", write_ret);
        if (write_ret < 0)
        {
            fprintf(logfp, "Failed writing content to socket on %d.\n",
                    connfd);
            fupdate(logfp);
            return -1;
        }

        if (write_ret == ct_size)
        {
            //dbg_cp2_printf("completed!\n");
            break;
        }

        ct_size = ct_size - write_ret;
        write_offset = write_offset + write_ret;
    }

    return 0;
}

ssize_t send_error(int connfd, SSL *client_context, int status_code) {
    Response_headers resp_hds;
    char resp_hds_text[MAX_TEXT + 1];
    char resp_ct_text[MAX_TEXT + 1];
    ssize_t ret = 0;
    memset(&resp_hds, 0, sizeof(Response_headers));
    memset(resp_hds_text, 0, MAX_TEXT + 1);
    memset(resp_ct_text, 0, MAX_TEXT + 1);

    strncpy(resp_hds.status_line.http_version, "HTTP/1.1",
            MAX_SIZE_S);
    strncpy(resp_hds.general_header.cache_control, "no-cache",
            MAX_SIZE_S);
    strncpy(resp_hds.general_header.connection, "keep-alive",
            MAX_SIZE_S);
    char *time_GMT = get_rfc1123_date();
    strncpy(resp_hds.general_header.date, time_GMT,
            MAX_SIZE_S);
    free(time_GMT);
    strncpy(resp_hds.general_header.paragma, "no-cache",
            MAX_SIZE_S);
    strncpy(resp_hds.general_header.transfer_encoding, "identity",
            MAX_SIZE_S);
    strncpy(resp_hds.response_header.server, "liso/1.0",
            MAX_SIZE_S);
    strncpy(resp_hds.entity_header.allow, "GET, HEAD, POST",
            MAX_SIZE_S);
    strncpy(resp_hds.entity_header.content_encoding, "identity",
            MAX_SIZE_S);
    strncpy(resp_hds.entity_header.content_language, "en",
            MAX_SIZE_S);
    get_error_content(status_code, resp_ct_text,
                      &resp_hds);
    get_response_headers(resp_hds_text, &resp_hds);
    ret = write_to_socket(connfd, client_context, resp_hds_text,
                          resp_ct_text, NULL,
                          resp_hds.entity_header.content_length);
    if (ret < 0) {
        return -1;
    }
    return 0;
}

int decode_asc(char *str)
{
    char str_decoded[MAX_SIZE + 1];
    memset(str_decoded, 0, MAX_SIZE + 1);
    size_t length = strlen(str);
    if (length < 3) {
        return 200;
    }
    size_t i, j;
    j = 0;
    for (i = 0; i < length;)
    {
        if (str[i] == '%')
        {
            char ch = 0;
            if (i + 1 >= length || i + 2 >= length) {
                return 400;
            }
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

    strncpy(str, str_decoded, MAX_SIZE);

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

ssize_t Close_conn(int connfd, pools *p) {
    dbg_cp3_printf("entering Close_conn\n");
    if (p->clientfd[connfd] > 1) {
        dbg_cp3_printf("pipefd: %d closed\n", connfd);
        Close(connfd);
    }
    else {
        if (p->SSL_client_ctx[connfd] != NULL) {
            SSL_shutdown(p->SSL_client_ctx[connfd]);
            SSL_free(p->SSL_client_ctx[connfd]);
            dbg_cp3_printf("connfd %d close\n", connfd);
            Close(connfd);
        }
        else if (p->close_fin[connfd] == 1 && p->remain_req[connfd] == 0) {
            dbg_cp3_printf("connfd %d close\n", connfd);
            Close(connfd);
        }
        else {
            char buf[1];
            int if_close = recv(connfd, buf, 1, MSG_PEEK);
            int sock_error = errno;

            if (if_close > 0) {
                return 0;
            }
            else if ((if_close == -1) && (sock_error == EWOULDBLOCK)) {
                return 0;
            }
            else
            {
                dbg_cp3_printf("connfd %d close\n", connfd);
                Close(connfd);
            }
        }
    }
    FD_CLR(connfd, &p->active_set);
    p->clientfd[connfd] = -1;
    p->SSL_client_ctx[connfd] = NULL;
    p->ign_first[connfd] = 0;
    p->too_long[connfd] = 0;
    p->close_fin[connfd] = 0;
    p->remain_req[connfd] = 0;
    memset(p->cached_buf[connfd], 0, REQ_BUF_SIZE + 1);
    free(p->cached_req[connfd]);
    p->cached_req[connfd] = NULL;
    memset(p->clientip[connfd], 0, MAX_SIZE_S + 1);
    return 0;
}

ssize_t Close(int fd) {
    ssize_t ret = close(fd);
    if (ret < 0) {
        fprintf(logfp, "Failed closing connection ");
        fprintf(logfp, "file descriptor %d.\n", fd);
        fupdate(logfp);
        return -1;
    }
    return 0;
}

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

    ret = write_to_socket(connfd, NULL, resp_htext, NULL, NULL, 0);
    if (ret < 0) {
        fprintf(logfp, "Failed sending reponse to fd%d\n", connfd);
        fupdate(logfp);
        return -1;
    }

    return 0;
}

void inline fupdate(FILE *fp)
{
    fflush(fp);
    fsync(logfd);
}

ssize_t if_exist(char *file_name) {
    dbg_cp3_printf("line 1630\n");
    FILE *fp = NULL;
    fp = fopen(file_name, "r");
    dbg_cp3_printf("line 1633\n");
    if (fp == NULL) {
        dbg_cp3_printf("line 1635\n");
        int i = 0;
        for (i = 0; i < 8; i++) {
            dbg_cp3_printf("@@@\n");
        }
        return 0;
    }
    else {
        dbg_cp3_printf("line 1637\n");
        fclose(fp);
        return 1;
    }
}