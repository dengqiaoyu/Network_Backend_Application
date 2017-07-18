#ifndef _DEBUG_H_
#define _DEBUG_H_

#include <stdio.h>  /* for perror */
#include <sys/types.h>
#include "packet.h"
#include "request.h"
#include "response.h"

#ifdef DEBUG
extern unsigned int debug;
#define DPRINTF(level, fmt, args...) \
        do { if (debug & (level)) fprintf(stderr, fmt , ##args ); } while(0)
#define DEBUG_PERROR(errmsg) \
        do { if (debug & DEBUG_ERRS) perror(errmsg); } while(0)
#else
#define DPRINTF(args...)
#define DEBUG_PERROR(args...)
#endif

//#define DEBUG_CP1
#ifdef DEBUG_CP1
#define dbg_cp1_printf(...) printf(__VA_ARGS__)
#define dbg_cp1_fprintf(...) fprintf(__VA_ARGS__)
#else
#define dbg_cp1_printf(...)
#define dbg_cp1_fprintf(...)
#endif

/*
 * The format of this should be obvious.  Please add some explanatory
 * text if you add a debugging value.  This text will show up in
 * -d list.  This list is processed by debugparse.pl to create the
 * help file automatically.
 */
#define DEBUG_NONE      0x00    // DBTEXT:  No debugging
#define DEBUG_ERRS      0x01    // DBTEXT:  Verbose error reporting
#define DEBUG_INIT      0x02    // DBTEXT:  Debug initialization
#define DEBUG_SOCKETS   0x04    // DBTEXT:  Debug socket operations
#define DEBUG_PROCESSES 0x08    // DBTEXT:  Debug processes (fork/reap/etc)
#define DEBUG_SPIFFY    0x10    // DBTEXT:  Debug the spiffy sending code

#define DEBUG_ALL  0xffffffff

#ifdef __cplusplus
extern "C" {
#endif
int set_debug(char *arg);  /* Returns 0 on success, -1 on failure */
#ifdef __cplusplus
}
#endif

void printf_requests(request_struct *request);
void printf_packet(packet_sturct *packet);
void printf_responses(response_struct *response);
void printf_pay_load(char *pay_load);

#endif /* _DEBUG_H_ */