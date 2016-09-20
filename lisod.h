#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <errno.h>
#include <sys/socket.h>
#include <netdb.h>

#define BUF_SIZE 65535
#define MAXLINE 4096
#define LISTENQ 1024
#define REQUEST_BUF_SIZE 8192
#define SOCKET_RECV_BUF_SIZE 65536
#define S_SELECT_TIMEOUT 0
#define US_SELECT_TIMEOUT 1000
#define S_RECV_TIMEOUT 0
#define US_RECV_TIMEOUT 2000

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

void sigtstp_handler();
int check_argv(int argc, char **argv, parameters *lisod_param);
int open_listenfd(char *port);
void init_pool(int listenfd, pools *p);
int add_client(int connfd, pools *p);
int server_clients(pools *p);