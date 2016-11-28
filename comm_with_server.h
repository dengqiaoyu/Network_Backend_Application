#ifndef COMM_WITH_SERVER_H
#define COMM_WITH_SERVER_H

#include "proxy.h"

int8_t set_conn(pools_t *p, int connfd, char *fake_ip, char *www_ip,
                char *hostname, char *port);
int8_t assemble_req(send2s_req_t *send2s_req, Requests *req_rover);
send2s_req_t *form_request2s(Requests *req_rover, pools_t *pool, \
    manifest_t *mani,throughput_t * thr_info, int clientfd);
int8_t req_send2s(int connfd, pools_t *p);
inline uint8_t check_req_type(char *http_uri);
inline send2s_req_t *find_last_send2s_req(send2s_req_t *);

#endif