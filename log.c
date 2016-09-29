#include <stdio.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include "log.h"

char *get_local_date();

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
    fprintf(logfp, "*                HTTPS Server Start                   *\n");
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
    fprintf(logfp, "*           End Time: %s         *\n", get_local_date());
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