/*
 * peer.c
 *
 * Authors: Ed Bardsley <ebardsle+441@andrew.cmu.edu>,
 *          Dave Andersen
 * Class: 15-441 (Spring 2005)
 *
 * Skeleton for 15-441 Project 2.
 *
 */

#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "request.h"
#include "debug.h"
#include "spiffy.h"
#include "bt_parse.h"
#include "input_buffer.h"


void peer_run(bt_config_t *config);

int main(int argc, char **argv)
{
    bt_config_t config;

    bt_init(&config, argc, argv);

    DPRINTF(DEBUG_INIT, "peer.c main beginning\n");

#ifdef TESTING
    config.identity = 1; // your group number here
    strcpy(config.chunk_file, "chunkfile");
    strcpy(config.has_chunk_file, "haschunks");
#endif

    bt_parse_command_line(&config);

#ifdef DEBUG
    if (debug & DEBUG_INIT)
    {
        bt_dump_config(&config);
    }
#endif

    peer_run(&config);
    return 0;
}


void process_inbound_udp(int sock)
{
#define BUFLEN 1500
    struct sockaddr_in from;
    socklen_t fromlen;
    char buf[BUFLEN];

    fromlen = sizeof(from);
    spiffy_recvfrom(sock, buf, BUFLEN, 0, (struct sockaddr *) &from, &fromlen);

    printf("PROCESS_INBOUND_UDP SKELETON -- replace!\n"
           "Incoming message from %s:%d\n%s\n\n",
           inet_ntoa(from.sin_addr),
           ntohs(from.sin_port),
           buf);
}

void process_get(request_struct *request)
{
    printf("PROCESS GET SKELETON CODE CALLED.  Fill me in!  (%s, %s)\n",
           request->get_chunk_file, request->out_put_file);
}

void handle_user_input(char *line, void *cbdata, request_struct *request)
{
    ssize_t ret = 0;
    ret = sscanf(line, "GET %1024s %1024s", request->get_chunk_file,
                 request->out_put_file);
    if (ret);
    {
        if (strlen(request->out_put_file) > 0)
        {
            process_get(request);
        }
    }
}


void peer_run(bt_config_t *config)
{
    int sock;
    struct sockaddr_in myaddr;
    fd_set readfds;
    struct user_iobuf *userbuf;

    if ((userbuf = create_userbuf()) == NULL)
    {
        perror("peer_run could not allocate userbuf");
        exit(-1);
    }

    if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)) == -1)
    {
        perror("peer_run could not create socket");
        exit(-1);
    }

    bzero(&myaddr, sizeof(myaddr));
    myaddr.sin_family = AF_INET;
    myaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    myaddr.sin_port = htons(config->myport);

    if (bind(sock, (struct sockaddr *) &myaddr, sizeof(myaddr)) == -1)
    {
        perror("peer_run could not bind socket");
        exit(-1);
    }

    spiffy_init(config->identity, (struct sockaddr *)&myaddr, sizeof(myaddr));

    while (1)
    {
        int nfds;
        FD_SET(STDIN_FILENO, &readfds);
        FD_SET(sock, &readfds);

        nfds = select(sock + 1, &readfds, NULL, NULL, NULL);

        if (nfds > 0)
        {
            if (FD_ISSET(sock, &readfds))
            {
                process_inbound_udp(sock);
            }

            if (FD_ISSET(STDIN_FILENO, &readfds))
            {
                request_struct request;
                bzero(&request, sizeof(request));
                process_user_input(STDIN_FILENO, userbuf, &request,
                                   handle_user_input, "Currently unused");
            }
        }
    }
}
