/******************************************************************************
 *                          lisod: HTTPS1.1 SERVER                            *
 *                          15-641 Computer Network                           *
 *                                hlp_func.h                                  *
 * This head file is for file hlp_func.c's head file requirement and function *
 * declaration                                                                *
 * Author: Qiaoyu Deng                                                        *
 * Andrew ID: qdeng                                                           *
 ******************************************************************************/
#ifndef HLP_FUNC
#define HLP_FUNC
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int decode_asc(char *str);
int convert2path(char *uri);
int decode_asc(char *str);
ssize_t Close(int fd);
ssize_t search_last_position(char *str1, char *str2);
ssize_t search_first_position(char *str1, char *str2);
void fupdate(FILE *fp);
char *get_rfc1123_date();
char *get_last_modified_date(time_t *t);
#endif