/******************************************************************************
 *                          lisod: HTTPS1.1 SERVER                            *
 *                          15-641 Computer Network                           *
 *                              By Qiaoyu Deng                                *
 *                             AndrewID: qdeng                                *
 * This server can handle basic GET, HEAD and POST methods that are defined in*
 * RFC 2616, and support basic CGI program execution.                         *
 * This program uses select for reading and writing, and all of socket IO is  *
 * unblock. Everytime it receives connection from client, it will create a new*
 * file descriptor for each client and add it in to read select, after it     *
 * generates response, it will put all the response to sending list of        *
 * corresponding client, and add the client file descriptor into write select.*
 * Waiting for next write ready.                                              *
 * Here is what I use to create request list and select pool:                 *
 * |  fd7  |->|  fd8  |->|  fd7  |->|  fd7  |->    ...   ->|fd1022|->|fd1023| *
 *     |                                                                      *
 * ---------     -------------------------------             array            *
 * | req 1 | --> | HTTP version, method and url| -->header1, header2, header3,*
 * ---------     -------------------------------                              *
 *     |                                                                      *
 * ---------                                                                  *
 * | req 2 |                                                                  *
 * ---------                                                                  *
 *     |                                                                      *
 * ---------                                                                  *
 * | req 3 |                                                                  *
 * ---------                                                                  *
 * Here is what I use to create send list and select pool:                    *
 * |  fd7  |->|  fd8  |->|  fd7  |->|  fd7  |->    ...   ->|fd1022|->|fd1023| *
 *     |                                                                      *
 * ---------                                                                  *
 * |headers| This is for static request                                       *
 * | body  |                                                                  *
 * ---------                                                                  *
 *     |                                                                      *
 * ---------                                                                  *
 * |headers|                                                                  *
 * | body  |                                                                  *
 * ---------                                                                  *
 *     |                                                                      *
 * ---------                                                                  *
 * |headers|                                                                  *
 * | body  |                                                                  *
 * ---------                                                                  *
 *     |                                                                      *
 * ---------                                                                  *
 * |       | This is for dynamic request                                      *
 * |  CGI  |                                                                  *
 * |       |                                                                  *
 * ---------                                                                  *
 * select will choose every fd to see if it is write ready, and send the      *
 * in the sending list                                                        *
 ******************************************************************************/
