#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "input_buffer.h"
#include "request.h"


struct user_iobuf *create_userbuf() {
    struct user_iobuf *b;
    b = malloc(sizeof(struct user_iobuf));
    if (!b) return NULL;

    b->buf = malloc(USERBUF_SIZE + 1);
    if (!b->buf) {
        free(b);
        return NULL;
    }

    b->cur = 0;
    bzero(b->buf, USERBUF_SIZE + 1);
    return b;
}

void process_user_input(int fd, struct user_iobuf *userbuf,
                        request_struct *request,
                        void (*handle_line)(char *, void *, request_struct *, packet2send_sturct *, peer_list_struct *),
                        packet2send_sturct *sending_list,
                        peer_list_struct *peer_list,
                        void *cbdata)
{
    int nread;
    char *ret;

    assert(userbuf != NULL);
    assert(userbuf->buf != NULL);

    /* A real program would propagate this error back to the select loop or
     * implement some other form of error handling */

    if (userbuf->cur >= (USERBUF_SIZE - 1)) {
        fprintf(stderr, "process_user_input error:  buffer full;  line too long!\n");
        exit(-1);
    }

    nread = read(fd, userbuf->buf + userbuf->cur,
                 (USERBUF_SIZE - userbuf->cur));

    if (nread > 0) {
        userbuf->cur += nread;
    }

    while ((ret = strchr(userbuf->buf, '\n')) != NULL) {
        *ret = '\0';
        handle_line(userbuf->buf, cbdata, request, sending_list, peer_list);
        /* Shift the remaining contents of the buffer forward */
        memmove(userbuf->buf, ret + 1, USERBUF_SIZE - (ret - userbuf->buf));
        userbuf->cur -= (ret - userbuf->buf + 1);
    }

}
