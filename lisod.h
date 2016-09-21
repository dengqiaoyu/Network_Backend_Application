#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <errno.h>
#include <netdb.h>
#include <fcntl.h>
#include <errno.h>
#include <netdb.h>
#include <time.h>

#define BUF_SIZE 65535
#define MAXLINE 4096
#define LISTENQ 1024
#define REQUEST_BUF_SIZE 8192
#define SOCKET_RECV_BUF_SIZE 65536
#define S_SELECT_TIMEOUT 0
#define US_SELECT_TIMEOUT 1000
#define S_RECV_TIMEOUT 0
#define US_RECV_TIMEOUT 2000
#define SUCCESS 0
#define MAX_SIZE 4096
#define MAX_SIZE_SMALL 64


//#define DEBUG_CP1
#ifdef DEBUG_CP1
/* When debugging is enabled, the underlying functions get called */
#define dbg_cp1_printf(...) printf(__VA_ARGS__)
#else
#define dbg_cp1_printf(...)
#endif

#define DEBUG_CP2
#ifdef DEBUG_CP2
#define dbg_cp2_printf(...) printf(__VA_ARGS__)
#else
#define dbg_cp2_printf(...)
#endif

typedef struct parameters
{
    char http_port[MAXLINE];
    char https_port[MAXLINE];
    char log_file[MAXLINE];
    char lock_file[MAXLINE];
    char www_folder[MAXLINE];
    char cgi_script_path[MAXLINE];
    char private_key_file[MAXLINE];
    char certificated_file[MAXLINE];
} parameters;

typedef struct pools
{
    int maxfd;
    fd_set active_set;
    fd_set ready_set;
    int num_ready;
    int maxi;
    int clientfd[FD_SETSIZE];
    int if_ignore_first[FD_SETSIZE];
    int if_too_long[FD_SETSIZE];
    char cached_buffer[FD_SETSIZE][REQUEST_BUF_SIZE + 1];
} pools;

//Header field
typedef struct
{
    char header_name[MAX_SIZE];
    char header_value[MAX_SIZE];
} Request_header;

//HTTP Request Header
typedef struct Requests
{
    char http_version[MAX_SIZE_SMALL];
    char http_method[MAX_SIZE_SMALL];
    char http_uri[MAX_SIZE];
    Request_header *headers;
    struct Requests *next_request;
    int header_count;
} Requests;

typedef struct
{
    char connection[MAX_SIZE_SMALL];
    char accept_charset[MAX_SIZE_SMALL];
    char accept_encoding[MAX_SIZE_SMALL];
    char accept_language[MAX_SIZE_SMALL];
    char host[MAX_SIZE];
    char user_agent[MAX_SIZE];
} Request_analyzed;

typedef struct
{
    char http_version[MAX_SIZE_SMALL];
    char status_code[MAX_SIZE_SMALL];
    char reason_phrase[MAX_SIZE_SMALL];
} Status_line;

typedef struct
{
    char cache_control[MAX_SIZE_SMALL];
    char connection[MAX_SIZE_SMALL];
    char date[MAX_SIZE_SMALL];
    char paragma[MAX_SIZE_SMALL];
    char trailer[MAX_SIZE_SMALL];
    char transfer_encoding[MAX_SIZE_SMALL];
    char upgrade[MAX_SIZE_SMALL];
    char via[MAX_SIZE_SMALL];
    char warning[MAX_SIZE_SMALL];
} General_header;

typedef struct
{
    char accept_ranges[MAX_SIZE_SMALL];
    char etag[MAX_SIZE_SMALL];
    char proxy_authenticate[MAX_SIZE_SMALL];
    char retry_after[MAX_SIZE_SMALL];
    char server[MAX_SIZE_SMALL];
    char vary[MAX_SIZE_SMALL];
    char www_authenticate[MAX_SIZE_SMALL];
    int age;
    char location[MAX_SIZE];
} Response_header;

typedef struct
{
    char allow[MAX_SIZE_SMALL];
    char content_encoding[MAX_SIZE_SMALL];
    char content_language[MAX_SIZE_SMALL];
    long content_length;
    char content_md5[MAX_SIZE_SMALL];
    char content_range[MAX_SIZE_SMALL];
    char content_type[MAX_SIZE_SMALL];
    char expries[MAX_SIZE_SMALL];
    char last_modified[MAX_SIZE_SMALL];
    char entension_header[MAX_SIZE_SMALL];
    char content_location[MAX_SIZE];
} Entity_header;

typedef struct
{
    Status_line *status_line;
    General_header *general_header;
    Response_header *response_header;
    Entity_header *entity_header;
} Response_headers;


void sigtstp_handler();
int check_argv(int argc, char **argv, parameters *lisod_param);
int open_listenfd(char *port);
void init_pool(int listenfd, pools *p);
int add_client(int connfd, pools *p);
int server_clients(pools *p);
void destory_requests(Requests *requests);
void print_request(Requests *requests);
int Close_connection(int connfd, int index);

Requests* parse(char *socket_recv_buf, size_t recv_buf_size , int socketFd,
               pools *p);

int init_log(char *log_file, int argc, char **argv);
int close_log(FILE *logfp);
char *get_current_time();