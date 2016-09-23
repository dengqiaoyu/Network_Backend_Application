#include "lisod.h"

/**
* Given a char buffer returns the parsed request headers
*/
void initiate_request(Requests *request);

Requests * parse(char *socket_recv_buf, size_t recv_buf_size, int socketFd,
                 pools *p)
{
    //Differant states in the read_state machine
    enum Request_Read_State {
        STATE_START = 0, STATE_CR, STATE_CRLF, STATE_CRLFCR, STATE_CRLFCRLF
    };
    enum Request_Read_State read_state;

    size_t recv_buf_offset = 0;
    size_t request_buf_offset = 0;

    char ch = 0;
    char request_buffer[REQUEST_BUF_SIZE + 1];
    memset(request_buffer, 0, REQUEST_BUF_SIZE + 1);
    size_t request_size = 0;
    size_t request_count = 0;

    char *chached_buffer = p->cached_buffer[socketFd];
    memset(chached_buffer, 0, REQUEST_BUF_SIZE + 1);

    int if_ignore_first = p->if_ignore_first[socketFd];
    int if_too_long = p->if_too_long[socketFd];
    int if_contain_2crlf = 0;
    ssize_t read_count = 0;
    ssize_t full_requests_size = 0;

    Requests *requests_ptr = NULL;
    Requests *request_last_ptr = NULL;
    Requests *request = NULL;

    int ret = 0;

    //dbg_cp2_printf("socket_recv_buf in parse.c:[\n%s]\n", socket_recv_buf);
    //dbg_cp2_printf("if_ignore_first: %d\n", if_ignore_first);
    //dbg_cp2_printf("if_too_long: %d\n", if_too_long);
    //dbg_cp2_printf("chached_buffer[0]: %d\n", chached_buffer[0]);

    //dbg_cp2_printf("parse.c: line 46\n");
    if (search_first_position(socket_recv_buf, "\r\n\r\n") != -1)
    {
        //dbg_cp2_printf("parse.c: line 49\n");
        if_contain_2crlf = 1;
    }
    else
    {
        //dbg_cp2_printf("parse.c: line 54\n");
        if_contain_2crlf = 0;
    }

    //dbg_cp2_printf("parse.c: line 55\n");
    if (chached_buffer[0] != 0)
    {
        request_size = strlen(chached_buffer);
        read_count = -request_size;
        memset(request_buffer, 0, REQUEST_BUF_SIZE + 1);
        strncpy(request_buffer, chached_buffer, REQUEST_BUF_SIZE);
        request_buf_offset = request_size;
    }
    else
    {
        if (if_ignore_first == 1)
        {
            read_count = search_first_position(socket_recv_buf, "\r\n\r\n") + 4;
            recv_buf_offset = read_count;
        }
    }

    //dbg_cp2_printf("parse.c: line 72\n");
    // dbg_cp2_printf("if_contain_2crlf: %d\n", if_contain_2crlf);
    if (if_contain_2crlf == 1)
    {
        full_requests_size =
            search_last_position("\r\n\r\n", socket_recv_buf) + 4;
        while (read_count != full_requests_size)
        {
            read_state = STATE_START;
            while (read_state != STATE_CRLFCRLF) {
                char expected = 0;
                if (recv_buf_offset == recv_buf_size)
                    break;
                ch = socket_recv_buf[recv_buf_offset++];
                request_size++;
                if (request_size < REQUEST_BUF_SIZE)
                {
                    request_buffer[request_buf_offset++] = ch;
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
            //dbg_cp2_printf("parse.c: line 115\n");
            //dbg_cp2_printf("@@request_buffer: [\n%s]\n", request_buffer);
            if (request_size <= REQUEST_BUF_SIZE)
            {
                request = (Requests *) malloc(sizeof(Requests));
                initiate_request(request);
                set_parsing_options(request_buffer, request_size, request);
                yyrestart();
                if (yyparse() != SUCCESS)
                {
                    free(request->headers);
                    request->headers = NULL;
                    free(request);
                }
                else
                {
                    // int index;
                    // dbg_cp2_printf("headers:\n");
                    // for (index = 0; index < request->header_count; index++)
                    // {
                    //     dbg_cp2_printf("%d:%s: %s\n", index,
                    //                    request->headers[index].header_name,
                    //                    request->headers[index].header_value);
                    // }
                    // printf("----------------------------------------------\n");

                    if (request_last_ptr != NULL)
                    {
                        request_last_ptr->next_request = request;
                        dbg_cp2_printf("Impossible!\n");
                    }
                    else
                    {
                        requests_ptr = request;
                    }
                    request_count++;
                    request_last_ptr = request;
                }
                //dbg_cp2_printf("parse.c: line 153\n");
            }
            else
            {
                printf("------------------------------------------\n");
                printf("Request too long\r\n\r\n----\n");
            }
            read_count = read_count + request_size;
            memset(request_buffer, 0, REQUEST_BUF_SIZE);
            request_size = 0;
            request_buf_offset = 0;
        }
        //dbg_cp2_printf("parse.c: line 163\n");
        if (full_requests_size != recv_buf_size)
        {
            size_t length = strlen(&socket_recv_buf[full_requests_size]);
            if (length <= REQUEST_BUF_SIZE)
            {
                memset(chached_buffer, 0, REQUEST_BUF_SIZE + 1);
                strncpy(chached_buffer, &socket_recv_buf[full_requests_size],
                        REQUEST_BUF_SIZE);
                if_too_long = 0;
                if_ignore_first = 0;
            }
            else
            {
                if_too_long = 1;
                if_ignore_first = 1;
            }
        }
    }
    else
    {
        if (if_ignore_first == 0)
        {
            if (chached_buffer[0] != 0)
            {
                size_t new_length = strlen(chached_buffer)
                                    + recv_buf_size;
                if (new_length <= REQUEST_BUF_SIZE)
                {
                    strncpy(chached_buffer + strlen(chached_buffer),
                            socket_recv_buf,
                            REQUEST_BUF_SIZE - strlen(chached_buffer));
                    if_too_long = 0;
                    if_ignore_first = 0;
                }
                else
                {
                    if_too_long = 1;
                    if_ignore_first = 1;
                }
            }
            else
            {
                size_t length = recv_buf_size;
                if (length < REQUEST_BUF_SIZE)
                {
                    strncpy(chached_buffer, socket_recv_buf,
                            REQUEST_BUF_SIZE);
                    if_too_long = 0;
                    if_ignore_first = 0;
                }
                else
                {
                    if_too_long = 1;
                    if_ignore_first = 1;
                }
            }
        }
    }

    p->if_ignore_first[socketFd] = if_ignore_first;
    p->if_too_long[socketFd] = if_too_long;

    return requests_ptr;
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

void initiate_request(Requests *request)
{
    memset(request->http_version, 0, MAX_SIZE_SMALL + 1);
    memset(request->http_method, 0, MAX_SIZE_SMALL + 1);
    memset(request->http_uri, 0, MAX_SIZE_SMALL + 1);
    request->headers = (Request_header *) malloc(sizeof(Request_header) * 1);
    request->next_request = NULL;
    request->header_count = 0;
}
