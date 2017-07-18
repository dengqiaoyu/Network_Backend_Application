/******************************************************************************
 *                          lisod: HTTPS1.1 SERVER                            *
 *                          15-641 Computer Network                           *
 *                                  parse.c                                   *
 * This file contains the functions that are used supporting parsing requests *
 * and hand in request text to lex and yacc to get request hearder and entity *
 * the parse.c has some error handling features that have not been tested due *
 * to the limit of time, it needs further tests.                              *
 * Author: Qiaoyu Deng                                                        *
 * Andrew ID: qdeng                                                           *
 ******************************************************************************/

#include "proxy.h"
#include "hlp_func.h"

#define SUCCESS 0
#define F_MELONG 1 // yacc uses to indicate http method too long error
#define F_URLONG 2 // ... http URL too long error
#define F_VELONG 3 // ... http version too long error 
#define F_HNLONG 4 // ... header name too long error
#define F_HVLONG 5 // ... header value too long error

// helper function
void initiate_request(Requests *req);
ssize_t if_contain_ebody(Requests *req);
// Used by yacc
void set_parsing_options(char *buf, size_t siz, Requests *parsing_request);
int yyparse();
void yyrestart();

Requests * parse(char *skt_recv_buf, size_t recv_buf_size, int socketfd,
                 pools_t *p) {
    //Differant states in the read_state machine
    enum Request_Read_State {
        STATE_START = 0, STATE_CR, STATE_CRLF, STATE_CRLFCR, STATE_CRLFCRLF
    };
    enum Request_Read_State read_state;

    size_t recv_buf_offset = 0;
    size_t req_buf_offset = 0;

    char ch = 0;
    char req_buffer[REQ_BUF_SIZE + 1];
    memset(req_buffer, 0, REQ_BUF_SIZE + 1);
    size_t req_size = 0;
    size_t req_count = 0;

    char *cached_buf = p->cached_buf[socketfd];

    int ign_first = p->ign_first[socketfd];
    int too_long = p->too_long[socketfd];
    int if_2crlf = 0;
    int end_with_ebody = 0;
    size_t hdr_offset_end = 0;
    // For request_buf that have no valid request area, but end with
    // "3r123rqwPOST / HTTP/1.1"
    size_t hdr_offset_end2 = 0;
    ssize_t read_count = 0;
    ssize_t full_req_size = 0;

    Requests *reqs_ptr = NULL;
    Requests *req_last_ptr = NULL;
    Requests *req = NULL;

    ssize_t ret = 0;

    // Judge whether has valid \r\n\r\n ending
    if (search_first_position(skt_recv_buf, "\r\n\r\n") != -1) {
        if_2crlf = 1;
    }
    else {
        if_2crlf = 0;
    }

    // Last request have not ended
    if (cached_buf[0] != 0) {
        req_size = strlen(cached_buf);
        read_count = -req_size;
        memset(req_buffer, 0, REQ_BUF_SIZE + 1);
        strncpy(req_buffer, cached_buf, REQ_BUF_SIZE);
        req_buf_offset = req_size;
    }
    else if (ign_first == 1) {
        // if indicated by ign_first, which means the first part of request
        // should be ignored due to too long error
        read_count = search_first_position(skt_recv_buf, "\r\n\r\n") + 4;
        recv_buf_offset = read_count;
        req = (Requests *) malloc(sizeof(Requests));
        initiate_request(req);
        req->error = 400;
        strncpy(req->http_method, "Request too long.", MAX_SIZE_S);
        if (req_last_ptr != NULL)
        {
            req_last_ptr->next_req = req;
        }
        else
        {
            reqs_ptr = req;
        }
        req_count++;
        req_last_ptr = req;
    }
    else if (p->cached_req[socketfd] != NULL) {
        // request is complete, but it has entity body that have not been read
        // yet
        size_t remain_size = p->cached_req[socketfd]->entity_len
                             - strlen(p->cached_req[socketfd]->entity_body);
        // The remaining part of body is all in the buffer
        if (remain_size <= recv_buf_size) {
            strncat(p->cached_req[socketfd]->entity_body, skt_recv_buf,
                    remain_size);
            // Next request will start at thi spoint
            hdr_offset_end2 = remain_size;
            read_count = remain_size;
            recv_buf_offset = read_count;
            if (req_last_ptr != NULL) {
                req_last_ptr->next_req = p->cached_req[socketfd];
            }
            else {
                reqs_ptr = p->cached_req[socketfd];
            }
            req_count++;
            req_last_ptr = p->cached_req[socketfd];
            p->cached_req[socketfd] = NULL;
        }
        else {
            // The remaining part of body is not all in the buffer
            strncat(p->cached_req[socketfd]->entity_body, skt_recv_buf,
                    recv_buf_size);
            if_2crlf = 0;
        }
    }

    // If end with at least one \r\n\r\n
    if (if_2crlf == 1) {
        // Find the valid request ending
        full_req_size =
            search_last_position("\r\n\r\n", skt_recv_buf) + 4;
        // State machine will put one request into req_buffer everytime for
        // lex and yacc
        while (read_count != full_req_size) {
            read_state = STATE_START;
            while (read_state != STATE_CRLFCRLF) {
                char expected = 0;
                if (recv_buf_offset == recv_buf_size)
                    break;
                ch = skt_recv_buf[recv_buf_offset++];
                req_size++;
                if (req_size < REQ_BUF_SIZE) {
                    req_buffer[req_buf_offset++] = ch;
                }

                switch (read_state) {
                case STATE_START:
                case STATE_CRLF:
                    expected = '\r';
                    break;
                case STATE_CR:
                case STATE_CRLFCR:
                    expected = '\n';
                    break;
                default:
                    read_state = STATE_START;
                    continue;
                }

                if (ch == expected)
                    read_state++;
                else
                    read_state = STATE_START;
            }

            size_t if_req_cached = 0;
            req = (Requests *) malloc(sizeof(Requests));
            initiate_request(req);
            if (cached_buf[0] != 0) {
                memset(p->cached_buf[socketfd], 0, REQ_BUF_SIZE + 1);
            }
            // if the length of request is within valid range, eg 8192
            if (req_size <= REQ_BUF_SIZE) {
                set_parsing_options(req_buffer, req_size, req);
                yyrestart();
                ret = yyparse();
                // handle with syntex error
                if (ret != SUCCESS) {
                    switch (ret) {
                    case F_MELONG:
                        req->error = 501;
                        break;
                    case F_URLONG:
                        req->error = 414;
                        break;
                    case F_VELONG:
                        req->error = 505;
                        break;
                    case F_HNLONG:
                        req->error = 400;
                        break;
                    case F_HVLONG:
                        req->error = 400;
                        break;
                    default:
                        req->error = 400;
                        break;
                    }
                }
                else {
                    req->error = 200;
                    // judage whether it has entitybody
                    req->entity_len = if_contain_ebody(req);
                    if (req->entity_len < 0) {
                        req->error = 400;
                        req->entity_len = 0;
                    }
                    if (req->entity_len) {
                        //read entity body right after the request
                        if ((read_count + req_size) == full_req_size) {
                            // There is some text after valid request, which
                            // should be the entity body
                            if (full_req_size != recv_buf_size) {
                                size_t end_ebody_len =
                                    recv_buf_size - full_req_size;
                                // remaining part is just all of enitity body
                                if (req->entity_len == end_ebody_len) {
                                    end_with_ebody = 1;
                                    req->entity_body =
                                        malloc(end_ebody_len + 1);
                                    memset(req->entity_body, 0, end_ebody_len + 1);
                                    strncpy(req->entity_body,
                                            &skt_recv_buf[full_req_size],
                                            end_ebody_len);
                                }
                                else if (req->entity_len < end_ebody_len) {
                                    // remaining part is all of enitity body
                                    // plus next request
                                    // the position where next request starts
                                    hdr_offset_end = req->entity_len;
                                    req->entity_body =
                                        malloc(req->entity_len + 1);
                                    memset(req->entity_body, 0,
                                           req->entity_len + 1);
                                    strncpy(req->entity_body,
                                            &skt_recv_buf[full_req_size],
                                            req->entity_len);
                                }
                                else {
                                    // remaining part is not all of enitity body
                                    // which should be saved Temporarily
                                    end_with_ebody = -1;
                                    if_req_cached = 1;
                                    p->cached_req[socketfd] = req;
                                    req->entity_body =
                                        malloc(req->entity_len + 1);
                                    memset(req->entity_body, 0,
                                           req->entity_len + 1);
                                    strncpy(req->entity_body,
                                            &skt_recv_buf[full_req_size],
                                            end_ebody_len);
                                }
                            }
                            else {
                                // The entity body is right after the next read
                                if_req_cached = 1;
                                p->cached_req[socketfd] = req;
                                req->entity_body =
                                    malloc(req->entity_len + 1);
                                memset(req->entity_body, 0,
                                       req->entity_len + 1);
                            }
                        }
                        else {
                            // Entity is contained in the requests part, which
                            // should have two or more requests
                            req->entity_body = malloc(req->entity_len + 1);
                            memset(req->entity_body, 0, req->entity_len + 1);
                            strncpy(req->entity_body,
                                    &skt_recv_buf[recv_buf_offset],
                                    req->entity_len);
                            recv_buf_offset = recv_buf_offset + req->entity_len;
                            read_count = read_count + req->entity_len;
                        }
                    }
                }
            }
            else {
                req->error = 400;
            }

            // If request need not to be saved to get its entity in next read
            if (if_req_cached == 0) {
                if (req_last_ptr != NULL) {
                    req_last_ptr->next_req = req;
                }
                else {
                    reqs_ptr = req;
                }
                req_count++;
                req_last_ptr = req;
            }

            // Moving the buffer reader
            read_count = read_count + req_size;
            memset(req_buffer, 0, REQ_BUF_SIZE);
            req_size = 0;
            req_buf_offset = 0;
        }

        // The remaining part ends with incomplete request, put it into buffer
        if (full_req_size != recv_buf_size && end_with_ebody == 0)
        {
            size_t length =
                strlen(&skt_recv_buf[full_req_size + hdr_offset_end]);
            if (length <= REQ_BUF_SIZE)
            {
                strncpy(cached_buf,
                        &skt_recv_buf[full_req_size + hdr_offset_end],
                        REQ_BUF_SIZE);
                too_long = 0;
                ign_first = 0;
            }
            else
            {
                too_long = 1;
                ign_first = 1;
            }
        }
    }
    else if (p->cached_req[socketfd] == NULL)
    {
        // if the data in read buffer is not a complete request and it is not an
        // entity body, save it as request.

        //  If request is not too long, ignore this part of data otherwise
        if (ign_first == 0)
        {

            // If cache has something inside, add new data behind that
            if (cached_buf[0] != 0)
            {
                size_t new_length = strlen(cached_buf)
                                    + recv_buf_size;
                if (new_length <= REQ_BUF_SIZE)
                {
                    strncpy(cached_buf + strlen(cached_buf),
                            skt_recv_buf,
                            REQ_BUF_SIZE - strlen(cached_buf));
                    too_long = 0;
                    ign_first = 0;
                }
                else
                {
                    too_long = 1;
                    ign_first = 1;
                }
            }
            else
            {
                // cache is NULL, add them all to cache

                size_t length = recv_buf_size;
                if (length < REQ_BUF_SIZE)
                {
                    strncpy(cached_buf, skt_recv_buf + hdr_offset_end2,
                            REQ_BUF_SIZE);
                    too_long = 0;
                    ign_first = 0;
                }
                else
                {
                    too_long = 1;
                    ign_first = 1;
                }
            }
        }
    }

    p->ign_first[socketfd] = ign_first;
    p->too_long[socketfd] = too_long;

    return reqs_ptr;
}

/**
 * Create new headers for request
 * @param req request
 */
void initiate_request(Requests *req) {
    memset(req, 0, sizeof(Requests));
    req->headers = (Request_header *) malloc(sizeof(Request_header) * 1);
}

/**
 * Check whether a request has "Content-Length" field
 * @param  req request
 * @return     size if contain, or 0
 */
ssize_t if_contain_ebody(Requests *req) {
    size_t i = 0;
    for (i = 0; i < req->h_count; i ++) {
        if (!strcasecmp(req->headers[i].h_name, "content-length")) {
            return strtol(req->headers[i].h_value, NULL, 10);
        }
    }
    return 0;
}