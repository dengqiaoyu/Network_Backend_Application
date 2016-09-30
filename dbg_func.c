#include <lisod.h>
#include <dbg_func.h>


void print_settings(param *lisod_param)
{
    dbg_cp2_printf("Settings:\n");
    dbg_cp2_printf("http_port: %s\n", lisod_param->http_port);
    dbg_cp2_printf("https_port: %s\n", lisod_param->https_port);
    dbg_cp2_printf("Log file: %s\n", lisod_param->log);
    dbg_cp2_printf("lock file: %s\n", lisod_param->lock);
    dbg_cp2_printf("www folder: %s\n", lisod_param->www);
    dbg_cp2_printf("CGI script path: %s\n", lisod_param->cgi_scp);
    dbg_cp2_printf("private key file: %s\n", lisod_param->priv_key);
    dbg_cp2_printf("certificate file: %s\n", lisod_param->cert_file);
}

void print_request(Requests *reqs)
{
    Requests *req_rover = reqs;
    while (req_rover != NULL)
    {
        int index = 0;
        dbg_cp2_printf("Http Method %s\n", req_rover->http_method);
        dbg_cp2_printf("Http Version %s\n", req_rover->http_version);
        dbg_cp2_printf("Http Uri %s\n", req_rover->http_uri);
        for (index = 0; index < req_rover->h_count; index++) {
            dbg_cp2_printf("Request Header\n");
            dbg_cp2_printf("Header name %s Header Value %s\n",
                           req_rover->headers[index].h_name,
                           req_rover->headers[index].h_value);
        }
        dbg_cp2_printf("**********************************************************\n");
        req_rover = req_rover->next_req;
    }
}

void print_request_analyzed(Request_analyzed *request_anlzed)
{
    dbg_cp2_printf("connection: %s\n", request_anlzed->connection);
    dbg_cp2_printf("accept_charset: %s\n", request_anlzed->accept_charset);
    dbg_cp2_printf("accept_encoding: %s\n", request_anlzed->accept_encoding);
    dbg_cp2_printf("accept_language: %s\n", request_anlzed->accept_language);
    dbg_cp2_printf("host: %s\n", request_anlzed->host);
    dbg_cp2_printf("user_agent: %s\n", request_anlzed->user_agent);
}

void print_response_headers(Response_headers *response_headers)
{
    dbg_cp2_printf("%s %s %s\n",
                   response_headers->status_line.http_version,
                   response_headers->status_line.status_code,
                   response_headers->status_line.reason_phrase);
    dbg_cp2_printf("cache_control: %s\n",
                   response_headers->general_header.cache_control);
    dbg_cp2_printf("connection: %s\n",
                   response_headers->general_header.connection);
    dbg_cp2_printf("date: %s\n",
                   response_headers->general_header.date);
    dbg_cp2_printf("paragma: %s\n",
                   response_headers->general_header.paragma);
    dbg_cp2_printf("transfer_encoding: %s\n",
                   response_headers->general_header.transfer_encoding);
    dbg_cp2_printf("server: %s\n",
                   response_headers->response_header.server);
    dbg_cp2_printf("allow: %s\n",
                   response_headers->entity_header.allow);
    dbg_cp2_printf("content_encoding: %s\n",
                   response_headers->entity_header.content_encoding);
    dbg_cp2_printf("content_language: %s\n",
                   response_headers->entity_header.content_language);
    dbg_cp2_printf("content_length: %ld\n",
                   response_headers->entity_header.content_length);
    dbg_cp2_printf("content_type: %s\n",
                   response_headers->entity_header.content_type);
    dbg_cp2_printf("last_modified: %s\n",
                   response_headers->entity_header.last_modified);
}