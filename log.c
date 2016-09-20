#include "lisod.h"

int init_log(char *log_file, int argc, char **argv)
{
    mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
    int logfd = open(log_file, O_WRONLY | O_APPEND | O_CREAT, mode);
    int i, ret;
    if (logfd == -1)
    {
        fprintf(stderr, "Failed creating\\opening log file.\n");
        return -1;
    }
    int logfd_temp = dup(logfd);
    if (logfd_temp == -1)
    {
        fprintf(stderr, "Failed copying file descriptor.\n");
        return -1;
    }
    FILE *logfp = fdopen(logfd_temp, "a");
    fprintf(logfp, "\n\n\n\n");
    fprintf(logfp, "*******************************************************\n");
    fprintf(logfp, "*                    Server Start                     *\n");
    fprintf(logfp, "*          Start Time: %s       *\n", get_current_time());
    fprintf(logfp, "-------------------------------------------------------\n");
    fprintf(logfp, "Command Line:\n");
    for (i = 0; i < argc; i++)
    {
        fprintf(logfp, "%s ", argv[i]);
    }
    fprintf(logfp, "\n");
    fprintf(logfp, "-------------------------------------------------------\n");
    ret = fclose(logfp);
    if (ret != 0)
    {
        fprintf(stderr, "Failed close file pointer.\n");
        return -1;
    }
    return logfd;
}

char *get_current_time()
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