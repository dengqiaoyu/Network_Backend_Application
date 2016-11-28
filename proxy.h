/******************************************************************************
 *                          lisod: HTTPS1.1 SERVER                            *
 *                          15-641 Computer Network                           *
 *                                 lisod.h                                    *
 * This head file is for file lisod.c's head file requirement and function    *
 * declaration, and most part of function declaration is in here.             *
 * What's more, it also contains constant and structure definition for most   *
 * data structure.                                                            *
 * Author: Qiaoyu Deng                                                        *
 * Andrew ID: qdeng                                                           *
 ******************************************************************************/
#ifndef PROXY_H
#define PROXY_H
/*Head file*/
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <errno.h>
#include <netdb.h>
#include <fcntl.h>
#include <errno.h>
#include <netdb.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>
#include "hashtable.h"

#include "param_init.h"
#include "constants.h"

/**
 * Debug function that is used to print
 */
//#define DEBUG_CP1
#ifdef DEBUG_CP1
#define dbg_cp1_printf(...) printf(__VA_ARGS__)
#else
#define dbg_cp1_printf(...)
#endif

//#define DEBUG_CP2
#ifdef DEBUG_CP2
#define dbg_cp2_printf(...) printf(__VA_ARGS__)
#else
#define dbg_cp2_printf(...)
#endif

//#define DEBUG_CP3
#ifdef DEBUG_CP3
#define dbg_cp3_printf(...) printf(__VA_ARGS__)
#define dbg_cp3_fprintf(...) fprintf(__VA_ARGS__)
#else
#define dbg_cp3_printf(...)
#define dbg_cp3_fprintf(...)
#endif

//#define DEBUG_WSELET
#ifdef DEBUG_WSELET
#define dbg_wselet_printf(...) printf(__VA_ARGS__)
#define dbg_wselet_fprintf(...) fprintf(__VA_ARGS__)
#else
#define dbg_wselet_printf(...)
#define dbg_wselet_fprintf(...)
#endif

// #define DEBUG_CP1_P3
#ifdef DEBUG_CP1_P3
#define dbg_cp3_p3_printf(...) printf(__VA_ARGS__)
#define dbg_cp3_p3_fprintf(...) fprintf(__VA_ARGS__)
#else
#define dbg_cp3_p3_printf(...)
#define dbg_cp3_p3_fprintf(...)
#endif

#define DEBUG_CP1_D2
#ifdef DEBUG_CP1_D2
#define dbg_cp3_d2_printf(...) printf(__VA_ARGS__)
#define dbg_cp3_d2_fprintf(...) fprintf(__VA_ARGS__)
#else
#define dbg_cp3_d2_printf(...)
#define dbg_cp3_d2_fprintf(...)
#endif

/**
 * Structure definition
 */

/*Structure for one header and value per request*/
typedef struct
{
    char h_name[MAX_SIZE + 1];
    char h_value[MAX_SIZE + 1];
} Request_header;

/*Structure for one request containing all of information including headers*/
typedef struct Requests
{
    char http_version[MAX_SIZE_S + 1];
    char http_method[MAX_SIZE_S + 1];
    char http_uri[MAX_SIZE + 1];
    Request_header *headers;
    char *entity_body;
    ssize_t entity_len;
    struct Requests *next_req;
    size_t h_count;
    size_t error;
} Requests;

typedef struct send2s_req_s
{
    char request[REQ_BUF_SIZE];
    size_t len;
    size_t offset;
    struct send2s_req_s *next;
} send2s_req_t;

typedef struct s2c_data_list_s
{
    char data[BUF_SIZE];
    size_t len;
    size_t offset;
    struct s2c_data_list_s *next;
} s2c_data_list_t;

typedef struct bitrate_s
{
    int bitrate_num;
    int bitrate[100];
} bitrate_t;

typedef struct manifest_s
{
    int flag_send_f4m[FD_SETSIZE];
    send2s_req_t *f4m_req[FD_SETSIZE];
    //record the pointer fo request of download .f4m of each client
    bitrate_t *bitrate_rec[FD_SETSIZE];
    //available bitrate of each client's video file

}manifest_t;

typedef struct throughput_s
{
    int send_fra_req[FD_SETSIZE];
    struct timeval ts_rec[FD_SETSIZE];
    double thr_cur[FD_SETSIZE];//throughput current
}throughput_t;

typedef struct log_record_s
{
    time_t cur_time;
    double duration;
    double tput;
    double avg_tput;
    int req_bitrate;
    char server_ip[16];
    char chunk_name[20];

}log_record_t;

typedef struct pools_t_s
{
    fd_set active_rd_set;
    fd_set active_wt_set;
    fd_set ready_rd_set;
    fd_set ready_wt_set;
    int num_ready;
    int clientfd[FD_SETSIZE];
    int serverfd[FD_SETSIZE];
    size_t ign_first[FD_SETSIZE]; // used to ignore the first lines of request
    size_t too_long[FD_SETSIZE];  // indicate whether the quest is too long
    // indicate whether to close connection after transfering
    size_t close_fin[FD_SETSIZE];
    // Used to save incomplete request which has no valid \r\n\r\n ending
    char cached_buf[FD_SETSIZE][REQ_BUF_SIZE + 1];
    // Used to save complete request but having not yet receive full body
    Requests *cached_req[FD_SETSIZE];
    // Save client ip information
    char clientip[FD_SETSIZE][15 + 1];
    char serverip[FD_SETSIZE][15 + 1];
    int16_t fd_c2s[FD_SETSIZE];
    int16_t fd_s2c[FD_SETSIZE];
    send2s_req_t *send2s_list[FD_SETSIZE];
    s2c_data_list_t *s2c_list[FD_SETSIZE];
    log_record_t *log_rec_list[FD_SETSIZE];

    manifest_t *mani_info;
    throughput_t *thr_info;
    hashtable_t * ip2mani_ht;
    hashtable_t * ip2thr_ht;

    
} pools_t;




/*
 * Functions that are used to construct basic execution steps
 */
int open_listenfd(char *port);
void init_pool(int listenfd, pools_t *p);
ssize_t add_client(int connfd, pools_t *p, char *c_host);
ssize_t serve_clients(pools_t *p);
manifest_t * init_manifest();
throughput_t * init_throughput();
/*
 * Functions that are used to acomplish crucial features
 */
Requests* parse(char *socket_recv_buf, size_t recv_buf_size , int socketFd,
                pools_t *p);

/*
 * Functions that are used to release resources
 */
void destory_requests(Requests *requests);
ssize_t Close_conn(int connfd, pools_t *p);

/*
 * Functions that are used to handle max connection, but have not yet debugged
 */
ssize_t send_maxfderr(int connfd);
ssize_t write_to_socket(int connfd, char *resp_hds_text, char *resp_ct_text,
                        char *resp_ct_ptr, size_t body_len);
#endif