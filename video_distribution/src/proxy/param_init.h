#ifndef PARAM_INIT
#define PARAM_INIT

#include <stdint.h>
#include <stdio.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <unistd.h>

#define PARAM_MAXLEN 8096

typedef struct param
{
    char log[PARAM_MAXLEN + 1];
    float alpha;
    char lisn_port[6];
    char fake_ip[16];
    char dns_ip[16];
    char dns_port[6];
    char www_ip[16];
} param;

int get_argv(int argc, char **argv, param *lisod_param);
int init_log(char *log_file, int argc, char **argv);
void close_log(FILE *logfp);

#endif