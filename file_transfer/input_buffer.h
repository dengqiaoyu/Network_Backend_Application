#include <stdlib.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include "request.h"

#define USERBUF_SIZE 8191

struct user_iobuf {
    char *buf;
    unsigned int cur;
};

struct user_iobuf *create_userbuf();

void process_user_input(int fd, struct user_iobuf *userbuf,
                        request_struct *request,
                        void (*handle_line)(char *, void *, request_struct *, packet2send_sturct *, peer_list_struct *),
                        packet2send_sturct *sending_list,
                        peer_list_struct *peer_list,
                        void *cbdata);
