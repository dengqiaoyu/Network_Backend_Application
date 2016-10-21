#include <stdlib.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#define USERBUF_SIZE 8191

struct user_iobuf {
    char *buf;
    unsigned int cur;
};

struct user_iobuf *create_userbuf();
