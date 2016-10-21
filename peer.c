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

bt_config_t config;


void peer_run(bt_config_t *config);
void printf_requests(request_struct *request);
void process_user_input(int fd, struct user_iobuf *userbuf,
                        request_struct *request,
                        void (*handle_line)(char *, void *, request_struct *, item_to_send_struct *),
                        item_to_send_struct *sending_list,
                        void *cbdata);

int main(int argc, char **argv)
{
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

    dbg_cp1_printf("PROCESS_INBOUND_UDP SKELETON -- replace!\n"
                   "Incoming message from %s:%d\n",
                   inet_ntoa(from.sin_addr),
                   ntohs(from.sin_port));
}

void process_get(request_struct *request, item_to_send_struct *sending_list)
{
    dbg_cp1_printf("PROCESS GET SKELETON CODE CALLED.  Fill me in!  (%s, %s)\n",
                   request->get_chunk_file, request->out_put_file);
    init_whohas_request(request);
    add2sending_list(request->whohas_ptr, sending_list);
#ifdef DEBUG_CP1
    printf_requests(request);
#endif
}

void handle_user_input(char *line, void *cbdata, request_struct *request,
                       item_to_send_struct *sending_list)
{
    ssize_t ret = 0;
    ret = sscanf(line, "GET %1024s %1024s", request->get_chunk_file,
                 request->out_put_file);
    if (ret);
    {
        if (strlen(request->out_put_file) > 0)
        {
            process_get(request, sending_list);
        }
    }
}


void peer_run(bt_config_t *config)
{
    int sock;
    struct sockaddr_in myaddr;
    fd_set readfds, writefds;
    struct user_iobuf *userbuf;
    item_to_send_struct *sending_list;
    sending_list = malloc(sizeof(item_to_send_struct));
    bzero(sending_list, sizeof(request_item_struct));

    FD_ZERO(&readfds);
    FD_ZERO(&writefds);

    if ((userbuf = create_userbuf()) == NULL)
    {
        perror("peer_run could not allocate userbuf");
        exit(-1);
    }

    if ((sock = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_IP)) == -1)
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
        ssize_t ret = 0;
        FD_SET(STDIN_FILENO, &readfds);
        FD_SET(sock, &readfds);
        FD_SET(sock, &writefds);

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
                init_request(&request);
                process_user_input(STDIN_FILENO, userbuf, &request,
                                   handle_user_input, sending_list,
                                   "Currently unused");
            }

            if (FD_ISSET(sock, &writefds))
            {
                dbg_cp1_printf("Begin sending\n");
                if (sending_list->next != NULL)
                {
                    ret = send_request(sock, sending_list);
                    dbg_cp1_printf("ret: %ld\n", ret);
                }
            }
        }
    }
}
