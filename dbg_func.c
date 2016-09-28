#include <lisod.h>
#include <dbg_func.h>


void print_request(Requests *requests)
{
  Requests *request_rover = requests;
  while (request_rover != NULL)
  {
    int index = 0;
    dbg_cp2_printf("Http Method %s\n", request_rover->http_method);
    dbg_cp2_printf("Http Version %s\n", request_rover->http_version);
    dbg_cp2_printf("Http Uri %s\n", request_rover->http_uri);
    for (index = 0; index < request_rover->header_count; index++) {
      dbg_cp2_printf("Request Header\n");
      dbg_cp2_printf("Header name %s Header Value %s\n",
                     request_rover->headers[index].header_name,
                     request_rover->headers[index].header_value);
    }
    dbg_cp2_printf("**********************************************************\n");
    request_rover = request_rover->next_request;
  }
}

void print_request_analyzed(Request_analyzed *request_analyzed)
{
  dbg_cp2_printf("connection: %s\n", request_analyzed->connection);
  dbg_cp2_printf("accept_charset: %s\n", request_analyzed->accept_charset);
  dbg_cp2_printf("accept_encoding: %s\n", request_analyzed->accept_encoding);
  dbg_cp2_printf("accept_language: %s\n", request_analyzed->accept_language);
  dbg_cp2_printf("host: %s\n", request_analyzed->host);
  dbg_cp2_printf("user_agent: %s\n", request_analyzed->user_agent);
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