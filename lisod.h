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

#define BUF_SIZE 65536
#define MAXLINE 4096
#define LISTENQ 1024
#define REQ_BUF_SIZE 8192
#define SKT_READ_BUF_SIZE 8192
#define S_SELT_TIMEOUT 0
#define US_SELT_TIMEOUT 1000
#define SUCCESS 0
#define MAX_SIZE 4096
#define MAX_SIZE_S 64
#define MAX_TEXT 8192
#define MAX_MSG 65536
#define MAX_CGI_MSG 65536
#define TYPE_SIZE 5
#define ENVP_len 23
#define SCRIPT_NAME "/cgi"
#define MAX_CGI_ITER_COUNT 10
#define MAX_READ_ITER_COUNT 10
#define INIT_WRITE_BUG_SIZE 204800

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

#define DEBUG_WSELET
#ifdef DEBUG_WSELET
#define dbg_wselet_printf(...) printf(__VA_ARGS__)
#define dbg_wselet_fprintf(...) fprintf(__VA_ARGS__)
#else
#define dbg_wselet_printf(...)
#define dbg_wselet_fprintf(...)
#endif

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

//Header field
typedef struct
{
    char h_name[MAX_SIZE + 1];
    char h_value[MAX_SIZE + 1];
} Request_header;

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

typedef struct pools
{
    fd_set active_rd_set;
    fd_set active_wt_set;
    fd_set ready_rd_set;
    fd_set ready_wt_set;
    int num_ready;
    int clientfd[FD_SETSIZE];
    SSL *SSL_client_ctx[FD_SETSIZE];
    size_t ign_first[FD_SETSIZE];
    size_t too_long[FD_SETSIZE];
    size_t close_fin[FD_SETSIZE];
    char cached_buf[FD_SETSIZE][REQ_BUF_SIZE + 1];
    Requests *cached_req[FD_SETSIZE];
    Response_list *resp_list[FD_SETSIZE];
    char clientip[FD_SETSIZE][MAX_SIZE_S + 1];
} pools;

//HTTP Request Header

typedef struct
{
    char connection[MAX_SIZE_S];
    char user_agent[MAX_SIZE];
} Request_analyzed;

typedef struct
{
    char http_version[MAX_SIZE_S + 1];
    char status_code[MAX_SIZE_S + 1];
    char reason_phrase[MAX_SIZE_S + 1];
} Status_line;

typedef struct
{
    char cache_control[MAX_SIZE_S + 1];
    char connection[MAX_SIZE_S + 1];
    char date[MAX_SIZE_S + 1];
    char paragma[MAX_SIZE_S + 1];
    char transfer_encoding[MAX_SIZE_S + 1];
} General_header;

typedef struct
{
    char server[MAX_SIZE_S + 1];
} Response_header;

typedef struct
{
    char allow[MAX_SIZE_S + 1];
    char content_encoding[MAX_SIZE_S + 1];
    char content_language[MAX_SIZE_S + 1];
    size_t content_length;
    char content_type[MAX_SIZE_S + 1];
    char last_modified[MAX_SIZE_S + 1];
} Entity_header;

typedef struct
{
    Status_line status_line;
    General_header general_header;
    Response_header response_header;
    Entity_header entity_header;
} Response_headers;

int check_argv(int argc, char **argv, param *lisod_param);
int daemonize(char* lock_file);
int open_listenfd(char *port);
int open_tls_listenfd(char *tls_port, char *priv_key, char *cert_file);
void init_pool(int listenfd, int ssl_listenfd, pools *p);
ssize_t add_client(int connfd, pools *p, char *c_host, ssize_t if_ssl);
ssize_t serve_clients(pools *p);
void inline get_request_analyzed(Request_analyzed *req_anlzed,
                                 Requests *req);
ssize_t que_resp_static(Request_analyzed *req_anlzed, Requests *req, pools *p,
                        int connfd, SSL *client_context);
ssize_t que_resp_dynamic(Request_analyzed *req_anlzed, Requests *req, pools *p,
                         int connfd, SSL * client_context, int cgi_rspfd);
ssize_t que_error(Request_analyzed *req_anlzed,
                  int connfd, pools *p, int status_code);
int inline check_http_method(char *http_method);
void get_response_headers(char *response_headers_text,
                          Response_headers *response_headers);
void get_error_content(Request_analyzed *req_anlzed, int status_code,
                       char *resp_hds_text, size_t *hrd_len,
                       char *resp_ct_text, size_t *body_len);
int get_contentfd(Requests *request, char *resp_hds_text, size_t *hdr_len,
                  size_t *body_len, int *contentfd);
int inline get_file_type(char *file_name, char *file_type);
ssize_t write_to_socket(int connfd, SSL *client_context, char *resp_hds_text,
                        char *resp_ct_text, char *resp_ct_ptr, size_t ct_size);
ssize_t add_send_list(int connfd, pools *p, char *resp_hds_text,
                      size_t hdr_len, char *resp_ct_text,
                      char *resp_ct_ptr, size_t ct_len);
ssize_t send_response(int connfd, pools *p);

void get_envp(pools *p, int connfd, Requests *req,
              char *ENVP[ENVP_len], char *port);
void add_cgi_rspfd(int cgifd, int connfd, pools *p);
void execve_error_handler();
int decode_asc(char *str);
int convert2path(char *uri);
void destory_requests(Requests *requests);
ssize_t Close_conn(int connfd, pools *p);
ssize_t Close(int fd);
ssize_t send_maxfderr(int connfd);
void fupdate(FILE *fp);

Requests* parse(char *socket_recv_buf, size_t recv_buf_size , int socketFd,
                pools *p);
char *get_rfc1123_date();
char *get_last_modified_date(time_t *t);
ssize_t search_last_position(char *str1, char *str2);
ssize_t search_first_position(char *str1, char *str2);
