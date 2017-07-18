#ifndef GRAPH_H
#define GRAPH_H
#include <stdio.h>
#include <stdlib.h>
#include "hashtable.h"

typedef struct adj_ip_s
{
    char ip[16];
    size_t weight;
    struct adj_ip_s *prev;
    struct adj_ip_s *next;
} adj_ip_t;

typedef struct node_s
{
    char ip[16];
    ssize_t max_seq;
    adj_ip_t *adj_ip_list;
} node_t;

typedef struct graph_s
{
    size_t node_num;
    hashtable_t *ip2node_ht;
} graph_t;

typedef struct lsa_msg_s
{
    char ip[16];
    size_t seq;
    size_t adj_num;
    char adj_ip[1024][16];
} lsa_msg_t;

graph_t *init_graph();
void destroy_graph(graph_t *graph);
void update_graph(graph_t *graph, lsa_msg_t *lsa_msg);
void add_neighboor(graph_t *graph, adj_ip_t *adj_ip_list,
                   char *source, char *ip, size_t max_seq);
adj_ip_t *n_exists(adj_ip_t *adj_ip_list, char *ip);
void parse_lsa_line(lsa_msg_t *lsa_msg, char *line);
adj_ip_t *find_last_adj_ip(node_t *node);
void print_lsa_msg(lsa_msg_t *lsa_msg);
void print_graph(graph_t *graph);
void print_s_ip_array(char s_ip_array[1024][1024], size_t s_num);
#endif