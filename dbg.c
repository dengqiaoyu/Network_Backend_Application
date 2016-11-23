#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "param_init.h"
#include "proxy.h"

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

void print_req(Requests *req)
{
    Requests *req_rover = req;
    while (req_rover != NULL)
    {
        printf("http_version: %s\n", req_rover->http_version);
        printf("http_method: %s\n", req_rover->http_method);
        printf("http_uri: %s\n", req_rover->http_uri);
        printf("entity_len: %ld\n", req_rover->entity_len);
        printf("h_count: %ld\n", req_rover->h_count);
        size_t i = 0;
        for (i = 0; i < req_rover->h_count; i++)
        {
            printf("%s: %s\n", req_rover->headers[i].h_name, req_rover->headers[i].h_value);
        }
        printf("--------------------------------\n");
        req_rover = req_rover->next_req;
    }
}

void print_request2s(send2s_req_t *request2s)
{
    send2s_req_t *request2s_rover = request2s;
    printf("\n--------------request2s-----------\n");
    while (request2s_rover != NULL)
    {
        printf("%s\n", request2s_rover->request);
        printf("len: %ld\n", request2s_rover->len);
        printf("offset: %ld\n", request2s_rover->offset);
        request2s_rover = request2s_rover->next;
    }
    printf("--------------request2s-----------\n");
}