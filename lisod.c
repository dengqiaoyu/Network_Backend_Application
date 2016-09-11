#include "lisod.h"
#include "log.h"

FILE *logfp = NULL;
int logfd = -1;

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

    dbg_cp2_printf("----- Echo Server -----\n");

    lisod_param.HTTP_port[0] = '\0';
    lisod_param.log_file[0] = '\0';
    ret = check_argv(argc, argv, &lisod_param);
    if (ret < 0)
    {
        return -1;
    }

    //Temperary use
    strncpy(lisod_param.log_file, "./lisod.log\0", MAXLINE);
    dbg_cp2_printf("Settings:\n");
    dbg_cp2_printf("HTTP_port: %s\n", lisod_param.HTTP_port);
    dbg_cp2_printf("Log file: %s\n", lisod_param.log_file);

    logfd = init_log(lisod_param.log_file, argc, argv);
    if (logfd < 0)
    {
        return -1;
    }
    logfp = fdopen(logfd, "a");

    if ((listenfd = open_listenfd(lisod_param.HTTP_port)) < 0)
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

        if (check_clients(&pool) < 0)
        {
            fprintf(logfp, "check_clients Failed.\n");
        }
    }

    return 0;
    ret = fclose(logfp);
    if (ret != 0)
    {
        fprintf(stderr, "Failed close file pointer.\n");
        exit(1);
    }
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
        fprintf(stderr, "Usage: %s <HTTP port> <HTTPs port> <log file>\n",
                argv[0]);
        return -1;
    }

    if (atoi(argv[1]) < 1024 || atoi(argv[1]) > 65535)
    {
        fprintf(stderr, "Usage: HTTP port should be between 1024 and 65535.");
        return -1;
    }
    else
    {
        strncpy(lisod_param->HTTP_port, argv[1], MAXLINE);
        lisod_param->HTTP_port[MAXLINE - 1] = '\0';
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
        p->clientfd[i] = -1;
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

int check_clients(pools *p)
{
    int i, connfd, readret, read_or_not, writeret, write_offset;
    char buf[BUF_SIZE];
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
                memset(buf, 0, BUF_SIZE);
                readret = recv(connfd, buf, BUF_SIZE, MSG_WAITALL);
                dbg_cp1_printf("readret: %d\n", readret);
                if (readret < 0)
                {
                    fprintf(logfp, "Failed receiving data from fd %d.\n", connfd);
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
                else if (readret == 0)
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
                if (readret == sizeof(buf))
                {
                    dbg_cp1_printf("again!\n");
                    read_or_not = 1;
                }
                else
                    read_or_not = 0;

                write_offset = 0;
                while (1)
                {
                    writeret = send(connfd, buf + write_offset, readret,
                                    MSG_WAITALL);
                    dbg_cp1_printf("writeret: %d\n", writeret);
                    if (writeret < 0)
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

                    if (writeret == readret)
                    {
                        dbg_cp1_printf("completed!\n");
                        break;
                    }

                    readret = readret - writeret;
                    write_offset = write_offset + writeret;
                }
            }
        }
    }

    return 0;
}
