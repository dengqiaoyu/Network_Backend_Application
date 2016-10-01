#include "lisod.h"
#include <dbg_func.h>

#define SUCCESS 0
#define F_MELONG 1
#define F_URLONG 2
#define F_VELONG 3
#define F_HNLONG 4
#define F_HVLONG 5

/**
* Given a char buffer returns the parsed req headers
*/
void initiate_request(Requests *req);

Requests * parse(char *skt_recv_buf, size_t recv_buf_size, int socketfd,
                 pools *p) {
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
    memset(cached_buf, 0, REQ_BUF_SIZE + 1);

    int ign_first = p->ign_first[socketfd];
    int too_long = p->too_long[socketfd];
    int if_2crlf = 0;
    ssize_t read_count = 0;
    ssize_t full_req_size = 0;

    Requests *reqs_ptr = NULL;
    Requests *req_last_ptr = NULL;
    Requests *req = NULL;

    ssize_t ret = 0;

    //dbg_cp2_printf("skt_recv_buf in parse.c:[\n%s]\n", skt_recv_buf);
    //dbg_cp2_printf("ign_first: %d\n", ign_first);
    //dbg_cp2_printf("too_long: %d\n", too_long);
    //dbg_cp2_printf("cached_buf[0]: %d\n", cached_buf[0]);

    //dbg_cp2_printf("parse.c: line 46\n");
    if (search_first_position(skt_recv_buf, "\r\n\r\n") != -1) {
        //dbg_cp2_printf("parse.c: line 49\n");
        if_2crlf = 1;
    }
    else {
        //dbg_cp2_printf("parse.c: line 54\n");
        if_2crlf = 0;
    }

    //dbg_cp2_printf("parse.c: line 55\n");
    if (cached_buf[0] != 0) {
        req_size = strlen(cached_buf);
        read_count = -req_size;
        memset(req_buffer, 0, REQ_BUF_SIZE + 1);
        strncpy(req_buffer, cached_buf, REQ_BUF_SIZE);
        req_buf_offset = req_size;
    }
    else if (ign_first == 1) {
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

    //dbg_cp2_printf("parse.c: line 72\n");
    // dbg_cp2_printf("if_2crlf: %d\n", if_2crlf);
    if (if_2crlf == 1) {
        full_req_size =
            search_last_position("\r\n\r\n", skt_recv_buf) + 4;
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

            req = (Requests *) malloc(sizeof(Requests));
            initiate_request(req);
            if (req_size <= REQ_BUF_SIZE) {
                set_parsing_options(req_buffer, req_size, req);
                yyrestart();
                ret = yyparse();
                print_request(req);
                if (ret != SUCCESS) {
                    // TODO to be tested
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
                        strncpy(req->http_method, "Request header too long.",
                                MAX_SIZE_S);
                        break;
                    case F_HVLONG:
                        req->error = 400;
                        strncpy(req->http_method, "Request value too long.",
                                MAX_SIZE_S);
                        break;
                    default:
                        req->error = 400;
                        break;
                    }

                }
                else {
                    req->error = 200;

                }
            }
            else {
                req->error = 400;
                strncpy(req->http_method, "Request too long.", MAX_SIZE_S);
            }

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

            read_count = read_count + req_size;
            memset(req_buffer, 0, REQ_BUF_SIZE);
            req_size = 0;
            req_buf_offset = 0;
        }
        //dbg_cp2_printf("parse.c: line 163\n");
        if (full_req_size != recv_buf_size)
        {
            size_t length = strlen(&skt_recv_buf[full_req_size]);
            if (length <= REQ_BUF_SIZE)
            {
                memset(cached_buf, 0, REQ_BUF_SIZE + 1);
                strncpy(cached_buf, &skt_recv_buf[full_req_size],
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
    else
    {
        if (ign_first == 0)
        {
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
                size_t length = recv_buf_size;
                if (length < REQ_BUF_SIZE)
                {
                    strncpy(cached_buf, skt_recv_buf,
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

ssize_t search_last_position(char *str1, char *str2)
{
    size_t i;
    size_t last_position = -1;
    size_t str1_len = strlen(str1);
    size_t str2_len = strlen(str2);
    size_t end = str2_len - str1_len;
    for (i = 0; i <= end; i++)
    {
        if (!strncmp(str1, str2 + i, str1_len))
            last_position = i;
    }
    return last_position;
}

ssize_t search_first_position(char *str1, char *str2)
{
    //dbg_cp2_printf("parse.c: line 246\n");
    char *first_position = strstr(str1, str2);
    if (first_position != NULL)
    {
        return first_position - str1;
    }
    else
    {
        return -1;
    }
}

void initiate_request(Requests *req)
{
    memset(req, 0, sizeof(Requests));
    req->headers = (Request_header *) malloc(sizeof(Request_header) * 1);
}
