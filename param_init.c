#include <stdio.h>
#include <stdlib.h>
#include "param_init.h"
#include "hlp_func.h"

char *get_local_date();

int get_argv(int argc, char **argv, param *proxy_param)
{
    memset(proxy_param, 0, sizeof(param));
    if (argc < 8)
    {
        fprintf(stderr, "Usage: %s ", argv[0]);
        fprintf(stderr, "<log> ");
        fprintf(stderr, "<alpha> ");
        fprintf(stderr, "<listen-port> ");
        fprintf(stderr, "<fake-ip> ");
        fprintf(stderr, "<dns-ip> ");
        fprintf(stderr, "<dns-port> ");
        fprintf(stderr, "<www-ip>\n");
        fupdate(stderr);
        return -1;
    }

    if (strlen(argv[1]) > PARAM_MAXLEN)
    {
        fprintf(stderr, "Log file path too long.\n");
        fupdate(stderr);
        return -1;
    }
    else
    {
        strncpy(proxy_param->log, argv[1], PARAM_MAXLEN);
    }

    if (atof(argv[2]) < 0 || atof(argv[2]) > 1)
    {
        fprintf(stderr, "alpha should be between 0 and 1.\n");
        fupdate(stderr);
        return -1;
    }
    else
    {
        proxy_param->alpha = atof(argv[2]);
    }

    if (atoi(argv[3]) < 1024 || atoi(argv[3]) > 65535)
    {
        fprintf(stderr, "Usage: listen port should be between 1024 and 65535.\n");
        fupdate(stderr);
        return -1;
    }
    else
    {
        strncpy(proxy_param->lisn_port, argv[3], 5);
    }

    if (strlen(argv[4]) > 15)
    {
        fprintf(stderr, "Fake ip too long.\n");
        fupdate(stderr);
        return -1;
    }
    else
    {
        strncpy(proxy_param->fake_ip, argv[4], 15);
    }

    if (strlen(argv[5]) > 15)
    {
        fprintf(stderr, "Dns ip too long.\n");
        fupdate(stderr);
        return -1;
    }
    else
    {
        strncpy(proxy_param->dns_ip, argv[5], 15);
    }

    if (atoi(argv[6]) > 65535)
    {
        fprintf(stderr, "Usage: DNS port should be between 1024 and 65535.\n");
        fupdate(stderr);
        return -1;
    }
    else
    {
        strncpy(proxy_param->dns_port, argv[6], 5);
    }

    if (strlen(argv[7]) > 15)
    {
        fprintf(stderr, "Server ip too long.\n");
        fupdate(stderr);
        return -1;
    }
    else
    {
        strncpy(proxy_param->www_ip, argv[7], 15);
    }

    return 0;
}

int init_log(char *log_file, int argc, char **argv)
{
    size_t i;
    ssize_t ret;
    mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;

    int logfd = open(log_file, O_WRONLY | O_APPEND | O_CREAT, mode);
    if (logfd == -1) {
        fprintf(stderr, "Failed creating\\opening log file in init_log.\n");
        return -1;
    }

    int logfd_tmp = dup(logfd);
    if (logfd_tmp == -1) {
        fprintf(stderr, "Failed copying file descriptor in init_log.\n");
        return -1;
    }

    FILE *logfp = fdopen(logfd_tmp, "a");
    fprintf(logfp, "\n\n\n\n");
    fprintf(logfp, "*******************************************************\n");
    fprintf(logfp, "*                    Proxy Start                      *\n");
    fprintf(logfp, "*          Start Time: %s       *\n", get_local_date());
    fprintf(logfp, "*-----------------------------------------------------*\n");
    fprintf(logfp, "Command Line:\n");
    for (i = 0; i < argc; i++) {
        fprintf(logfp, "%s ", argv[i]);
    }
    fprintf(logfp, "\n");
    fprintf(logfp, "*-----------------------------------------------------*\n");

    ret = fclose(logfp);
    if (ret != 0) {
        fprintf(stderr, "Failed close file pointer in init_log.\n");
        return -1;
    }

    return logfd;
}

void close_log(FILE *logfp)
{
    ssize_t ret;
    fprintf(logfp, "Terminated by user.\n");
    fprintf(logfp, "*----------------------------------------------------*\n");
    fprintf(logfp, "*          End Time: %s        *\n", get_local_date());
    fprintf(logfp, "******************************************************\n");
    ret = fclose(logfp);
    if (ret != 0)
    {
        fprintf(stderr, "Failed close file pointer from close_log.\n");
    }
}

char *get_local_date()
{
    char *time_descrip = NULL;
    time_t t;
    struct tm *timenow;

    time(&t);
    timenow = localtime(&t);
    time_descrip = asctime(timenow);
    time_descrip[strlen(time_descrip) - 1] = '\0';
    return time_descrip;
}
