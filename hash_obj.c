#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "constant.h"
#include "bt_parse.h"
#include "hash_obj.h"
#include "debug.h"

extern bt_config_t config;

jwHashTable *init_haschunk_hash_table()
{
    ssize_t ret = 0;
    FILE *haschunk_file = fopen(config.has_chunk_file, "r");
    if (haschunk_file == NULL)
    {
        return NULL;
    }

    size_t haschunk_size = 0;
    char haschunk_line[64] = {0};
    while (fgets(haschunk_line, HASH_LINE_MAXSIZE, haschunk_file) != NULL)
    {
        haschunk_size++;
    }
    fseek (haschunk_file, 0, SEEK_SET);

    jwHashTable *haschunk_hash_table = create_hash(haschunk_size);
    while (fgets(haschunk_line, HASH_LINE_MAXSIZE, haschunk_file) != NULL)
    {
        long int chunk_id = 0;
        char chunk_hash[41] = {0};
        ret = sscanf(haschunk_line, "%ld %40s\n", &chunk_id, chunk_hash);
        if (ret == 0)
        {
            continue;
        }
        HASHRESULT hash_result = add_int_by_str(haschunk_hash_table,
                                                chunk_hash, chunk_id);
        if (hash_result != HASHOK)
        {
            printf("add_int_by_strc failed\n");
            fclose(haschunk_file);
            return NULL;
        }
    }
    fclose(haschunk_file);

    return haschunk_hash_table;
}