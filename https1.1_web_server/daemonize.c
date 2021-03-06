/******************************************************************************
 *                          lisod: HTTPS1.1 SERVER                            *
 *                          15-641 Computer Network                           *
 *                               daemonize.c                                  *
 * This file contains the functions that are used to supprt backend execution *
 * some part of code is copied from TA, and some thread-unsafe parts are fixed*
 * main function can use those functions to runing sliently.                  *
 * What's more, signal handler and exit method are provided within this file  *
 * Author: Qiaoyu Deng                                                        *
 * Andrew ID: qdeng                                                           *
 ******************************************************************************/

#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/ssl.h>
#include "log.h"

extern FILE *logfp;
extern int errfd;
extern int old_stdin;
extern int old_stdout;
extern int old_stderr;
extern SSL_CTX *ssl_context;

void signal_handler(int sig);
void liso_shutdown();
/***** Utility Functions *****/

/**
 * internal signal handler
 */
void signal_handler(int sig)
{
    switch (sig)
    {
    case SIGHUP:
        /* rehash the server */
        break;
    case SIGTERM:
        liso_shutdown();
        break;
    case SIGCHLD: {
        int child_stat = 0;
        pid_t child_pid = waitpid(-1, &child_stat, WNOHANG);
        if (child_pid != 0) {
            fprintf(logfp, "child %d terminated with %d\n", child_pid,
                    child_stat);
        }
    }
    default:
        break;
        /* unhandled signal */
    }
}

/**
 * daemonize the server
 * @param  lock_file the path of file that is used to limit only one server to
 *         run
 * @return           0 for EXIT_SUCCESS
 */
int daemonize(char* lock_file)
{
    /* drop to having init() as parent */
    int i, lfp, pid = fork();
    char str[256] = {0};
    if (pid < 0) exit(EXIT_FAILURE);
    if (pid > 0) exit(EXIT_SUCCESS);

    setsid();

    old_stdin = dup(STDIN_FILENO);
    old_stdout = dup(STDOUT_FILENO);
    old_stderr = dup(STDERR_FILENO);
    i = open("/dev/null", O_RDWR);

    dup2(i, STDIN_FILENO); /* stdin */
    dup2(i, STDOUT_FILENO); /* stdout */
    dup2(i, STDERR_FILENO); /* stderr */
    if (i > 2) {
        close(i);
    }
    umask(027); // rxw r-x ---

    lfp = open(lock_file, O_RDWR | O_CREAT, 0640); // rx- r-- ---

    if (lfp < 0)
        exit(EXIT_FAILURE); /* can not open */

    if (lockf(lfp, F_TLOCK, 0) < 0)
        exit(EXIT_SUCCESS); /* can not lock */

    /* only first instance continues */
    sprintf(str, "%d\n", getpid());
    write(lfp, str, strlen(str)); /* record pid to lockfile */

    signal(SIGCHLD, signal_handler); /* child terminate signal */
    signal(SIGPIPE, signal_handler); /* override pipe broken */
    signal(SIGHUP, signal_handler); /* hangup signal */
    signal(SIGTERM, signal_handler); /* software termination signal from kill */

    return EXIT_SUCCESS;
}

/**
 * Close server, and restore stdin, stdin, stderr
 */
void liso_shutdown()
{
    SSL_CTX_free(ssl_context);
    close_log(logfp);
    close(errfd);
    dup2(old_stdin, STDIN_FILENO);
    dup2(old_stdout, STDOUT_FILENO);
    dup2(old_stderr, STDERR_FILENO);
    printf("Server lisod terminated successfully.\n");

    exit(1);
}
