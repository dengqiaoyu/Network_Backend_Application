#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "param_init.h"

void print_argv(param *proxy_param)
{
    printf("----------------proxy_param start---------\n");
    printf("log: %s\n", proxy_param->log);
    printf("alpha: %f\n", proxy_param->alpha);
    printf("lisn_port: %s\n", proxy_param->lisn_port);
    printf("fake_ip: %s\n", proxy_param->fake_ip);
    printf("dns_ip: %s\n", proxy_param->dns_ip);
    printf("dns_port: %s\n", proxy_param->dns_port);
    printf("www_ip: %s\n", proxy_param->www_ip);
    printf("----------------proxy_param end------------\n");
}