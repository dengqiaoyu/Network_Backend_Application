#include <stdlib.h>
#include "proxy.h"

int8_t s2c_list_read_server(pools_t *p, int serverfd);
int8_t s2c_list_write_client(pools_t *p, int clientfd);
s2c_data_list_t *find_last_s2c_data(s2c_data_list_t *s2c_data);