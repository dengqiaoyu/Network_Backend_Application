#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "constant.h"
#include "bt_parse.h"
#include "hash_obj.h"
#include "debug.h"

extern bt_config_t config;

hashtable_t *init_haschunk_hash_table()
{
    ssize_t ret = 0;
    FILE *haschunk_file = fopen(config.has_chunk_file, "r");
    if (haschunk_file == NULL)
    {
        return NULL;
    }

    char haschunk_line[64] = {0};

    hashtable_t *haschunk_hash_table = ht_create(HASHTABLE_MINSIZE,
                                       HASHTABLE_MAXSIZE, NULL);
    while (fgets(haschunk_line, HASH_LINE_MAXSIZE, haschunk_file) != NULL)
    {
        size_t chunk_id = 0;
        char chunk_hash[41] = {0};
        ret = sscanf(haschunk_line, "%ld %40s\n", &chunk_id, chunk_hash);
        if (ret == 0)
        {
            continue;
        }
        // dbg_cp1_printf("chunk_hash: %s\n", chunk_hash);
        ret = ht_set_if_not_exists(haschunk_hash_table, chunk_hash, 40,
                                   &chunk_id, 8);
        if (ret == -1)
        {
            printf("ht_set_if_not_exists failed\n");
            fclose(haschunk_file);
            ht_destroy(haschunk_hash_table);
            return NULL;
        }
        else if (ret == 1)
        {
            printf("key already exists\n");
        }
        // ret = ht_exists(haschunk_hash_table, chunk_hash, 40);
        // dbg_cp1_printf("ret: %ld\n", ret);
    }
    fclose(haschunk_file);

    return haschunk_hash_table;
}