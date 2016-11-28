#include "proxy.h"


char * get_f4m_content(pools_t *p, int clientfd);
bitrate_t * parse_manifest(char *mani_file);