#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include "input_buffer.h"
#include "request.h"

void printline(char *line, void *cbdata, request_struct *unused,
               packet2send_sturct *sending_list, peer_list_struct *peer_list)
{
    printf("LINE:  %s\n", line);
    printf("CBDATA:  %s\n", (char *)cbdata);
}


int main() {


    struct user_iobuf *u;

    u = create_userbuf();
    assert(u != NULL);

    while (1) {
        process_user_input(STDIN_FILENO, u, NULL, printline, NULL, NULL,
                           "Cows moo!");
    }

    return 0;
}
