#include <stdio.h>
#include "request.h"
#include "bt_parse.h"
#include "debug.h"

extern bt_config_t config;

ssize_t init_whohas_request(request_struct *request);

ssize_t init_whohas_request(request_struct *request)
{
    ssize_t ret = 0;
    FILE *target_chunks_ptr = NULL;
    char target_chunk[HASH_LINE_MAXSIZE + 1] = {0};
    target_chunks_ptr = fopen(request->get_chunk_file, "r");
    if (target_chunks_ptr == NULL)
    {
        printf("chunk-file does not exist\n");
        return -1;
    }

    FILE *node_map_ptr = NULL;
    char node_info[NODE_LINE_MAXSIZE + 1] = {0};
    node_map_ptr = fopen(config.peer_list_file, "r");
    if (node_map_ptr == NULL)
    {
        printf("peer-list-file does not exist\n");
        return -1;
    }

    while (fgets(target_chunk, HASH_LINE_MAXSIZE, target_chunks_ptr) != NULL)
    {
        size_t chunk_id = 0;
        char hash_str[HASH_LEN + 1] = {0};
        ret = sscanf(target_chunk, "%ld %40s\n", &chunk_id, hash_str);
        if (ret == 0)
        {
            continue;
        }
        dbg_cp1_printf("Want: %ld %s\n", chunk_id, hash_str);
        while (fgets(node_info, NODE_LINE_MAXSIZE, node_map_ptr) != NULL)
        {
            size_t peer_id = 0;
            char peer_addr[16] = {0};
            unsigned short peer_port = -1;
            ret = sscanf(node_info, "%ld %16s %hu\n",
                         &peer_id, peer_addr, &peer_port);
            if (ret == 0)
            {
                continue;
            }
            dbg_cp1_printf("After parse: %ld %s %hu\n",
                           peer_id, peer_addr, peer_port);
            set_ip_port(request, peer_addr, peer_port);

        }
        fseek(node_map_ptr, 0, SEEK_SET);
    }

    return 1;
}

void set_ip_port(request_struct *request, char *peer_addr,
                 unsigned short peer_port)
{

}