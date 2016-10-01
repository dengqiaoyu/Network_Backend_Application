#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *DAY[] =
{ "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
static const char *MONTH[] =
{   "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};

char *get_rfc1123_date()
{
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

char *get_last_modified_date(time_t *t)
{
    int rfc1123_date_length = 29;
    struct tm tm;
    char *buf = (char *)malloc(rfc1123_date_length + 1);

    gmtime_r(t, &tm);

    strftime(buf, rfc1123_date_length + 1, "---, %d --- %Y %H:%M:%S GMT", &tm);
    memcpy(buf, DAY[tm.tm_wday], 3);
    memcpy(buf + 8, MONTH[tm.tm_mon], 3);

    return buf;
}