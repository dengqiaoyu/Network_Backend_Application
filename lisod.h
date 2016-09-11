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
    char HTTP_port[MAXLINE];
    char log_file[MAXLINE];
} parameters;

typedef struct pools
{
    int maxfd;
    fd_set active_set;
    fd_set ready_set;
    int num_ready;
    int maxi;
    int clientfd[FD_SETSIZE];
} pools;

void sigtstp_handler();
int check_argv(int argc, char **argv, parameters *lisod_param);
int open_listenfd(char *port);
void init_pool(int listenfd, pools *p);
int add_client(int connfd, pools *p);
int check_clients(pools *p);