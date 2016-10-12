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
#include <openssl/ssl.h>
#include <openssl/err.h>

/*Constant definition*/
#define BUF_SIZE 65536
#define MAXLINE 4096
#define LISTENQ 1024  // The max number of fd that a process can create 
#define REQ_BUF_SIZE 8192  // Buffer that is used to save un-complete request
#define SKT_READ_BUF_SIZE 8192  // The max number of bytes read from client
#define S_SELT_TIMEOUT 0  // Time out value for select
#define US_SELT_TIMEOUT 1000
#define SUCCESS 0  //  Used by parser.y
#define MAX_SIZE 4096  // the max size for request headers that is longer
#define MAX_SIZE_S 64  // the max size for request headers that is smaller
#define MAX_TEXT 8192
#define MAX_MSG 65536
#define MAX_CGI_MSG 65536  // Max size of message read from CGI program
#define TYPE_SIZE 5  // The number of content-type that server supports
#define ENVP_len 23  // The number of arguments needed by CGI program
#define SCRIPT_NAME "/cgi"
#define MAX_CGI_ITER_COUNT 10  // The max times of read from CGI at once
#define MAX_READ_ITER_COUNT 10 // The max times of read data from any fd

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

/**
 * Structure definition
 */
/*Structure for basic running arguments*/
typedef struct param
{
    char http_port[MAXLINE + 1];
    char https_port[MAXLINE + 1];
    char log[MAXLINE + 1];
    char lock[MAXLINE + 1];
    char www[MAXLINE + 1];
    char cgi_scp[MAXLINE + 1];
    char priv_key[MAXLINE + 1];
    char cert_file[MAXLINE + 1];
} param;

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

/*Structure for sending list that is used to arrange writing select feature*/
typedef struct Response_list
{
    char *headers;
    char *body;
    size_t hdr_len;
    size_t hdr_offset;
    size_t body_len;
    size_t body_offset;
    char is_body_map;
    struct Response_list *next;
} Response_list;

/*Structure for fd pools that is used to determine whether to read or write*/
typedef struct pools
{
    fd_set active_rd_set;
    fd_set active_wt_set;
    fd_set ready_rd_set;
    fd_set ready_wt_set;
    int num_ready;
    int clientfd[FD_SETSIZE];
    SSL *SSL_client_ctx[FD_SETSIZE];
    size_t ign_first[FD_SETSIZE]; // used to ignore the first lines of request
    size_t too_long[FD_SETSIZE];  // indicate whether the quest is too long
    // indicate whether to close connection after transfering
    size_t close_fin[FD_SETSIZE];
    // Used to save incomplete request which has no valid \r\n\r\n ending
    char cached_buf[FD_SETSIZE][REQ_BUF_SIZE + 1];
    // Used to save complete request but having not yet receive full body
    Requests *cached_req[FD_SETSIZE];
    // Used to save sending windows for every client by using write select
    Response_list *resp_list[FD_SETSIZE];
    // Save client ip information
    char clientip[FD_SETSIZE][MAX_SIZE_S + 1];
} pools;

typedef struct
{
    char connection[MAX_SIZE_S];
    char user_agent[MAX_SIZE];
} Request_analyzed;

/*
 * Functions that are used to construct basic execution steps
 */
int check_argv(int argc, char **argv, param *lisod_param);
int daemonize(char* lock_file);
int open_listenfd(char *port);
int open_tls_listenfd(char *tls_port, char *priv_key, char *cert_file);
void init_pool(int listenfd, int ssl_listenfd, pools *p);
ssize_t add_client(int connfd, pools *p, char *c_host, ssize_t if_ssl);
ssize_t serve_clients(pools *p);
/*
 * Functions that are used to acomplish crucial features
 */
Requests* parse(char *socket_recv_buf, size_t recv_buf_size , int socketFd,
                pools *p);
ssize_t que_resp_static(Request_analyzed *req_anlzed, Requests *req, pools *p,
                        int connfd, SSL *client_context);
ssize_t que_resp_dynamic(Request_analyzed *req_anlzed, Requests *req, pools *p,
                         int connfd, SSL * client_context, int cgi_rspfd);
ssize_t que_error(Request_analyzed *req_anlzed,
                  int connfd, pools *p, int status_code);
/*
 * Functions that are used to get response
 */
void inline get_request_analyzed(Request_analyzed *req_anlzed,
                                 Requests *req);
void get_error_content(Request_analyzed *req_anlzed, int status_code,
                       char *resp_hds_text, size_t *hrd_len,
                       char *resp_ct_text, size_t *body_len);
int get_contentfd(Requests *request, char *resp_hds_text, size_t *hdr_len,
                  size_t *body_len, int *contentfd);
/*
 * Functions that are used to arrange writing window
 */
ssize_t add_send_list(int connfd, pools *p, char *resp_hds_text,
                      size_t hdr_len, char *resp_ct_text,
                      char *resp_ct_ptr, size_t ct_len);
ssize_t send_response(int connfd, pools *p);

/*
 * Functions that are used to check arguments
 */
int inline check_http_method(char *http_method);
int inline get_file_type(char *file_name, char *file_type);

/*
 * Functions that are used to support CGI
 */
void get_envp(pools *p, int connfd, Requests *req,
              char *ENVP[ENVP_len], char *port);
void add_cgi_rspfd(int cgifd, int connfd, pools *p);
void execve_error_handler();

/*
 * Functions that are used to release resources
 */
void destory_requests(Requests *requests);
ssize_t Close_conn(int connfd, pools *p);

/*
 * Functions that are used to handle max connection, but have not yet debugged
 */
ssize_t send_maxfderr(int connfd);
ssize_t write_to_socket(int connfd, SSL *client_context, char *resp_hds_text,
                        char *resp_ct_text, char *resp_ct_ptr, size_t ct_size);