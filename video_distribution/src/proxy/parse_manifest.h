/******************************************************************************
 *                                 Video CDN                                  *
 *                          15-641 Computer Network                           *
 *                              parse_manifest.h                              *
 * This file contains the declaration of functions used in parsing manifest   *
 * file                                                                       *
 * Author: Qiaoyu Deng; Yangmei Lin                                           *
 * Andrew ID: qdeng; yangmeil                                                 *
 ******************************************************************************/
#include "proxy.h"


char * get_f4m_content(pools_t *p, int clientfd);
bitrate_t * parse_manifest(char *mani_file);