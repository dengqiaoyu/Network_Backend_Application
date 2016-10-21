#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include "input_buffer.h"
#include "request.h"

void process_user_input(int fd, struct user_iobuf *userbuf,
                        request_struct *request,
                        void (*handle_line)(char *, void *, request_struct *),
                        void *cbdata);

void printline(char *line, void *cbdata, request_struct *unused) {
    printf("LINE:  %s\n", line);
    printf("CBDATA:  %s\n", (char *)cbdata);
}


int main() {


    struct user_iobuf *u;

    u = create_userbuf();
    assert(u != NULL);

    while (1) {
        process_user_input(STDIN_FILENO, u, NULL, printline, "Cows moo!");
    }

    return 0;
}
