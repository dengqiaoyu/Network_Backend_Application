/******************************************************************************
 *                          lisod: HTTPS1.1 SERVER                            *
 *                          15-641 Computer Network                           *
 *                                cgi_func.c                                  *
 * This file contains functions that are used to support CGI service,         *
 * incluing getting parameters, adding file descriptor and error handling for *
 * cgi execution                                                              *
 * Author: Qiaoyu Deng                                                        *
 * Andrew ID: qdeng                                                           *
 ******************************************************************************/

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "lisod.h"


extern FILE *logfp;

// The name of required CGI environment arguements
static const char* ENVP_key[] = {
    "CONTENT_LENGTH",
    "CONTENT_TYPE",
    "GATEWAY_INTERFACE",
    "PATH_INFO",
    "QUERY_STRING",
    "REMOTE_ADDR",
    "REQUEST_METHOD",
    "REQUEST_URI",
    "SCRIPT_NAME",
    "SERVER_PORT",
    "SERVER_PROTOCOL",
    "SERVER_SOFTWARE",
    "HTTPS",
    "HOST_NAME",
    "HTTP_ACCEPT",
    "HTTP_REFERER",
    "HTTP_ACCEPT_ENCODING",
    "HTTP_ACCEPT_LANGUAGE",
    "HTTP_ACCEPT_CHARSET",
    "HTTP_COOKIE",
    "HTTP_USER_AGENT",
    "HTTP_CONNECTION",
    "HTTP_HOST",
    NULL
};

// The value of required CGI environment arguements
static const char* header_name_key[] = {
    "Content-Length",
    "Content-Type",
    "NULL",
    "NULL",
    "NULL",
    "NULL",
    "NULL",
    "NULL",
    "NULL",
    "NULL",
    "NULL",
    "NULL",
    "NULL",
    "Host",
    "Accept",
    "Referer",
    "Accept-Encoding",
    "Accept-Language",
    "Accept-Charset",
    "Cookie",
    "User-Agent",
    "Connection",
    "Host",
    NULL
};

/**
 * Parse environment arguements
 * @param p      pool
 * @param connfd fd of client
 * @param req    request
 * @param ENVP   environment arguements
 * @param port   http or https port
 */
void get_envp(pools *p, int connfd, Requests *req,
              char *ENVP[ENVP_len], char *port) {
    size_t i = 0;
    dbg_cp3_fprintf(stderr, "entering get_envp\n");
    while (header_name_key[i] != NULL) {
        switch (i) {
        case 2: // GATEWAY_INTERFACE
        {
            strncpy(ENVP[i], "GATEWAY_INTERFACE=CGI/1.1", 2 * MAX_SIZE + 1);
        }
        break;
        case 3: // PATH_INFO
        {
            size_t path_offset =
                search_first_position(req->http_uri, "/cgi") + 3 + 1;
            ssize_t query_offset = search_first_position(req->http_uri, "?");
            size_t path_len = 0;
            if (query_offset < 0) {
                path_len = strlen(req->http_uri) - path_offset;
            }
            else {
                path_len = query_offset - path_offset;
            }
            char path[MAX_SIZE] = {0};
            char hv_pair[(2 * MAX_SIZE + 1) + 1] = {0};
            if (path_offset < strlen(req->http_uri)) {
                strncpy(path, &(req->http_uri[path_offset]), path_len);
            }
            snprintf(hv_pair, 2 * MAX_SIZE + 1, "%s=%s", ENVP_key[i], path);
            strncpy(ENVP[i], hv_pair, 2 * MAX_SIZE + 1);
        }
        break;
        case 4: // QUERY_STRING
        {
            size_t query_offset = search_first_position(req->http_uri, "?") + 1;
            char query[MAX_SIZE] = {0};
            if (query_offset > 1 && query_offset < strlen(req->http_uri)) {
                strncpy(query, &(req->http_uri[query_offset]), MAX_SIZE);
            }
            char hv_pair[(2 * MAX_SIZE + 1) + 1] = {0};
            snprintf(hv_pair, 2 * MAX_SIZE + 1, "%s=%s", ENVP_key[i], query);
            strncpy(ENVP[i], hv_pair, 2 * MAX_SIZE + 1);
        }
        break;
        case 5: // REMOTE_ADDR
        {
            char hv_pair[(2 * MAX_SIZE + 1) + 1] = {0};
            snprintf(hv_pair, 2 * MAX_SIZE + 1, "%s=%s", ENVP_key[i],
                     p->clientip[connfd]);
            strncpy(ENVP[i], hv_pair, 2 * MAX_SIZE + 1);
        }
        break;
        case 6: // REQUEST_METHOD
        {
            char hv_pair[(2 * MAX_SIZE + 1) + 1] = {0};
            snprintf(hv_pair, 2 * MAX_SIZE + 1, "%s=%s", ENVP_key[i],
                     req->http_method);
            strncpy(ENVP[i], hv_pair, 2 * MAX_SIZE + 1);
        }
        break;
        case 7: // REQUEST_URI
        {
            char hv_pair[(2 * MAX_SIZE + 1) + 1] = {0};
            snprintf(hv_pair, 2 * MAX_SIZE + 1, "%s=%s", ENVP_key[i],
                     req->http_uri);
            strncpy(ENVP[i], hv_pair, 2 * MAX_SIZE + 1);
        }
        break;
        case 8: // SCRIPT_NAME
        {
            strncpy(ENVP[i], "SCRIPT_NAME=/cgi", 2 * MAX_SIZE + 1);
        }
        break;
        case 9: // SERVER_PORT
        {
            char hv_pair[(2 * MAX_SIZE + 1) + 1] = {0};
            snprintf(hv_pair, 2 * MAX_SIZE + 1, "%s=%s", ENVP_key[i],
                     port);
            strncpy(ENVP[i], hv_pair, 2 * MAX_SIZE + 1);
        }
        break;
        case 10: // SERVER_PROTOCOL
        {
            char hv_pair[(2 * MAX_SIZE + 1) + 1] = {0};
            snprintf(hv_pair, 2 * MAX_SIZE + 1, "%s=%s", ENVP_key[i],
                     "HTTP/1.1");
            strncpy(ENVP[i], hv_pair, 2 * MAX_SIZE + 1);
        }
        break;
        case 11: // SERVER_SOFTWARE
        {
            char hv_pair[(2 * MAX_SIZE + 1) + 1] = {0};
            if (!strncmp("HTTP/1.0", req->http_version, MAX_SIZE_S))
            {
                snprintf(hv_pair, 2 * MAX_SIZE + 1, "%s=%s", ENVP_key[i],
                         "Liso/1.0");
            }
            else if (!strncmp("HTTP/1.1", req->http_version, MAX_SIZE_S))
            {
                snprintf(hv_pair, 2 * MAX_SIZE + 1, "%s=%s", ENVP_key[i],
                         "Liso/1.0");
            }
            strncpy(ENVP[i], hv_pair, 2 * MAX_SIZE + 1);
        }
        break;
        case 12: // SERVER_SOFTWARE
        {
            char hv_pair[(2 * MAX_SIZE + 1) + 1] = {0};
            if (p->SSL_client_ctx[connfd] != NULL) {
                snprintf(hv_pair, 2 * MAX_SIZE + 1, "%s=%s", ENVP_key[i],
                         "on");
            }
            else {
                snprintf(hv_pair, 2 * MAX_SIZE + 1, "%s=%s", ENVP_key[i],
                         "off");
            }
            strncpy(ENVP[i], hv_pair, 2 * MAX_SIZE + 1);
        }
        break;
        default: // others
        {
            size_t index = 0;
            for (index = 0; index < req->h_count; index++) {
                char *hdr_name = req->headers[index].h_name;
                if (!strcasecmp(header_name_key[i], hdr_name)) {
                    char hv_pair[(2 * MAX_SIZE + 1) + 1] = {0};
                    snprintf(hv_pair, 2 * MAX_SIZE + 1, "%s=%s", ENVP_key[i],
                             req->headers[index].h_value);
                    strncpy(ENVP[i], hv_pair, 2 * MAX_SIZE + 1);
                    break;
                }
                else {
                    char hv_pair[(2 * MAX_SIZE + 1) + 1] = {0};
                    snprintf(hv_pair, 2 * MAX_SIZE + 1, "%s=", ENVP_key[i]);
                    strncpy(ENVP[i], hv_pair, 2 * MAX_SIZE + 1);
                }
            }
        }
        break;
        }
        i++;
    }
}

/**
 * Add fd that is used to read from CGI into select read
 * @param cgifd  fd pipe that can read from child
 * @param connfd fd of client
 * @param p      pool
 */
void add_cgi_rspfd(int cgifd, int connfd, pools *p) {
    FD_SET(cgifd, &p->active_rd_set);
    p->clientfd[cgifd] = connfd;
}

/**
 * Print error message into log
 */
void execve_error_handler()
{
    switch (errno)
    {
    case E2BIG:
        fprintf(logfp, "The total number of bytes in the environment \
(envp) and argument list (argv) is too large.\n");
        return;
    case EACCES:
        fprintf(logfp, "Execute permission is denied for the file or a \
script or ELF interpreter.\n");
        return;
    case EFAULT:
        fprintf(logfp, "filename points outside your accessible address \
space.\n");
        return;
    case EINVAL:
        fprintf(logfp, "An ELF executable had more than one PT_INTERP \
segment (i.e., tried to name more than one \
interpreter).\n");
        return;
    case EIO:
        fprintf(logfp, "An I/O error occurred.\n");
        return;
    case EISDIR:
        fprintf(logfp, "An ELF interpreter was a directory.\n");
        return;
    case ELIBBAD:
        fprintf(logfp, "An ELF interpreter was not in a recognised \
format.\n");
        return;
    case ELOOP:
        fprintf(logfp, "Too many symbolic links were encountered in \
resolving filename or the name of a script \
or ELF interpreter.\n");
        return;
    case EMFILE:
        fprintf(logfp, "The process has the maximum number of files \
open.\n");
        return;
    case ENAMETOOLONG:
        fprintf(logfp, "filename is too long.\n");
        return;
    case ENFILE:
        fprintf(logfp, "The system limit on the total number of open \
files has been reached.\n");
        return;
    case ENOENT:
        fprintf(logfp, "The file filename or a script or ELF interpreter \
does not exist, or a shared library needed for \
file or interpreter cannot be found.\n");
        return;
    case ENOEXEC:
        fprintf(logfp, "An executable is not in a recognised format, is \
for the wrong architecture, or has some other \
format error that means it cannot be \
executed.\n");
        return;
    case ENOMEM:
        fprintf(logfp, "Insufficient kernel memory was available.\n");
        return;
    case ENOTDIR:
        fprintf(logfp, "A component of the path prefix of filename or a \
script or ELF interpreter is not a directory.\n");
        return;
    case EPERM:
        fprintf(logfp, "The file system is mounted nosuid, the user is \
not the superuser, and the file has an SUID or \
SGID bit set.\n");
        return;
    case ETXTBSY:
        fprintf(logfp, "Executable was open for writing by one or more \
processes.\n");
        return;
    default:
        fprintf(logfp, "Unkown error occurred with execve().\n");
        return;
    }
}