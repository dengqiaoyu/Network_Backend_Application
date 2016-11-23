/******************************************************************************
 *                          lisod: HTTPS1.1 SERVER                            *
 *                          15-641 Computer Network                           *
 *                               hlp_func.c                                   *
 * This file contains the functions that are used for many small utilizations *
 * which are hard to classfy them into different part. So all of those        *
 * are put in here including url decoding, path transfering, warpper for close*
 * and string seraching function plus GMT time getter                         *
 * Author: Qiaoyu Deng                                                        *
 * Andrew ID: qdeng                                                           *
 ******************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hlp_func.h"

// Used for GMT time
static const char *DAY[] =
{ "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
static const char *MONTH[] =
{   "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};

#define MAX_SIZE 4096

extern FILE *logfp;
extern int logfd;

/**
 * covert %XX to ascii char
 * @param  str String that need to convert
 * @return     200 for valid url, 400 for unvalid
 */
int decode_asc(char *str) {
    char str_decoded[MAX_SIZE + 1];
    memset(str_decoded, 0, MAX_SIZE + 1);
    size_t length = strlen(str);
    if (length < 3) {
        return 200;
    }
    size_t i, j;
    j = 0;
    for (i = 0; i < length;) {
        if (str[i] == '%') {
            char ch = 0;
            if (i + 1 >= length || i + 2 >= length) {
                return 400;
            }
            if (str[i + 1] > 64 && str[i + 1] < 71) {
                ch = (str[i + 1] - 55) * 16;
            }
            else if (str[i + 1] > 96 && str[i + 1] < 103) {
                ch = (str[i + 1] - 87) * 16;
            }
            else if (str[i + 1] > 47 && str[i + 1] < 58) {
                ch = (str[i + 1] - 48) * 16;
            }
            else {
                return 400;
            }

            if (str[i + 2] > 64 && str[i + 2] < 71) {
                ch += str[i + 2] - 55;
            }
            else if (str[i + 2] > 96 && str[i + 2] < 103) {
                ch += str[i + 2] - 87;
            }
            else if (str[i + 2] > 47 && str[i + 2] < 58) {
                ch += str[i + 2] - 48;
            }
            else {
                return 400;
            }

            str_decoded[j] = ch;
            j++;
            i += 3;
        }
        else {
            str_decoded[j] = str[i];
            j++;
            i++;
        }
    }
    strncpy(str, str_decoded, MAX_SIZE);

    return 200;
}

/**
 * covert absolet path
 * @param  uri
 * @return     200 for valid url, 400 for unvalid
 */
int convert2path(char *uri)
{
    size_t slash_num = 0;
    size_t uri_len = strlen(uri);
    char uri_buf[MAX_SIZE] = {0};
    size_t i = 0;

    for (i = 0; i < uri_len; i++) {
        if (uri[i] == '/')
            slash_num++;
    }
    if (strstr(uri, "http://") != uri) {
        if ((strstr(uri, "/") != uri)) {
            if (strncmp(uri, "", MAX_SIZE) != 0) {
                return 400;
            }
            else {
                return 200;
            }
        }
        else {
            return 200;
        }
    }
    else if (slash_num < 3) {
        return 400;
    }
    else {
        char *start = strstr(&uri[7], "/");
        strncpy(uri_buf, start, MAX_SIZE);
        strncpy(uri, uri_buf, MAX_SIZE);
        return 200;
    }
}

/**
 * Warpper for close
 * @param  fd fd that needs to close
 * @return    [description]
 */
ssize_t Close(int fd) {
    ssize_t ret = close(fd);
    if (ret < 0) {
        fprintf(logfp, "Failed closing connection ");
        fprintf(logfp, "file descriptor %d.\n", fd);
        fupdate(logfp);
        return -1;
    }
    return 0;
}

/**
 * Force system update log write buffer
 * @param fp log file pointer
 */
void fupdate(FILE *fp)
{
    fflush(fp);
    fsync(logfd);
}

/**
 * Get the last postion of specific string
 * @param  str1 longer string
 * @param  str2 shorter string
 * @return      position of array, or -1 for no matching
 */
ssize_t search_last_position(char *str1, char *str2) {
    size_t i;
    size_t last_position = -1;
    size_t str1_len = strlen(str1);
    size_t str2_len = strlen(str2);
    size_t end = str2_len - str1_len;
    for (i = 0; i <= end; i++) {
        if (!strncmp(str1, str2 + i, str1_len))
            last_position = i;
    }
    return last_position;
}

/**
 * Get the first postion of specific string
 * @param  str1 longer string
 * @param  str2 shorter string
 * @return      position of array, or -1 for no matching
 */
ssize_t search_first_position(char *str1, char *str2) {
    char *first_position = strstr(str1, str2);
    if (first_position != NULL) {
        return first_position - str1;
    }
    else {
        return -1;
    }
}

/**
 * get GMT time
 * @return the string of GMT time, needs to free.
 */
char *get_rfc1123_date() {
    int rfc1123_date_length = 29;
    time_t t;
    struct tm tm;
    char *buf = (char *)malloc(rfc1123_date_length + 1);

    time(&t);
    gmtime_r(&t, &tm);

    strftime(buf, rfc1123_date_length + 1, "---, %d --- %Y %H:%M:%S GMT", &tm);
    memcpy(buf, DAY[tm.tm_wday], 3);
    memcpy(buf + 8, MONTH[tm.tm_mon], 3);

    return buf;
}


/**
 * Convert last_modified_date to GMT time
 * @param  t get from stat
 * @return   the string of GMT time, needs to free.
 */
char *get_last_modified_date(time_t *t) {
    int rfc1123_date_length = 29;
    struct tm tm;
    char *buf = (char *)malloc(rfc1123_date_length + 1);

    gmtime_r(t, &tm);

    strftime(buf, rfc1123_date_length + 1, "---, %d --- %Y %H:%M:%S GMT", &tm);
    memcpy(buf, DAY[tm.tm_wday], 3);
    memcpy(buf + 8, MONTH[tm.tm_mon], 3);

    return buf;
}