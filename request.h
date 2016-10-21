#include <stdio.h>
#include <stdlib.h>

#define PACKET_MAXSIZE 1500
#define PATH_MAXSIZE 1024
#define HASH_LINE_MAXSIZE 44
#define HASH_LEN 40
#define NODE_LINE_MAXSIZE 64
typedef enum {WHOHAS, IHAVE, GET, DATA, ACK, DENIED} packet_type_code_enum;

typedef struct packet_sturct
{
    char magic_number[2];
    char version_number[1];
    char packet_type[1];
    char header_length[2];
    char total_packet_length[2];
    char sequence_number[4];
    char acknowldgment_number[4];
    char pay_load[PACKET_MAXSIZE - 16];
} packet_sturct;

typedef struct request_item_struct
{
    char peer_addr[16];
    unsigned short peer_port;
    char unused[14];
    packet_sturct *packet_ptr;
    struct request_item_struct *next;
} request_item_struct;

typedef request_item_struct item_to_send_struct;

typedef struct request_struct
{
    char get_chunk_file[PATH_MAXSIZE];
    char out_put_file[PATH_MAXSIZE];
    request_item_struct *whohas_ptr;
    request_item_struct *get_ptr;
} request_struct;

void init_request(request_struct *request);
ssize_t init_whohas_request(request_struct *request);