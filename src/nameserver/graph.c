#include <stdio.h>
#include <stdlib.h>
#include "hashtable.h"
#include "graph.h"
#include "dijkstra.h"
#include "round_robin.h"

// int main(int argc, char **argv)
// {
//     FILE *lsa_file = fopen("topo1.lsa", "r");
//     FILE *server_file = fopen("topo1.servers", "r");

//     char line[1024] = {0};
//     graph_t *graph = init_graph();
//     while (fgets(line, 1023, lsa_file) != NULL)
//     {
//         lsa_msg_t lsa_msg;
//         parse_lsa_line(&lsa_msg, line);
//         update_graph(graph, &lsa_msg);
//     }
//     fclose(lsa_file);
//     print_graph(graph);

//     hashtable_t *c2s_ip_ht = ht_create(0, 1024, NULL);
//     char s_ip_array[MAX_S_NUM][MAX_LINE];
//     size_t i;
//     for (i = 0; i < 1024; i++)
//     {
//         memset(s_ip_array[i], 0, 1024);
//     }
//     size_t s_num = 0;
//     while (fgets(line, 1023, server_file) != NULL)
//     {
//         sscanf(line, "%s\n", s_ip_array[s_num]);
//         s_num++;
//     }
//     fclose(server_file);
//     printf("\n");
//     // print_s_ip_array(s_ip_array, s_num);
//     dijkstra(graph, c2s_ip_ht, s_ip_array, s_num);
//     print_c2s_ip_ht(c2s_ip_ht);
//     destroy_graph(graph);

//     server_loop_queue_t server_loop_queue;
//     memset(&server_loop_queue, 0, sizeof(server_loop_queue_t));
//     init_server_loop_queue(s_ip_array, s_num, &server_loop_queue);
//     char server_ip[MAX_LINE] = {0};
//     memset(server_ip, 0, MAX_LINE);
//     round_robin(&server_loop_queue, server_ip);
//     printf("server_ip: %s\n", server_ip);
//     memset(server_ip, 0, MAX_LINE);
//     round_robin(&server_loop_queue, server_ip);
//     printf("server_ip: %s\n", server_ip);
//     memset(server_ip, 0, MAX_LINE);
//     round_robin(&server_loop_queue, server_ip);
//     printf("server_ip: %s\n", server_ip);
//     memset(server_ip, 0, MAX_LINE);
//     round_robin(&server_loop_queue, server_ip);
//     printf("server_ip: %s\n", server_ip);

//     return 0;
// }

graph_t *init_graph()
{
    graph_t *graph = malloc(sizeof(graph_t));
    memset(graph, 0, sizeof(graph_t));
    graph->node_num = 0;
    graph->ip2node_ht = ht_create(0, 1024, NULL);
    return graph;
}

void destroy_graph(graph_t *graph)
{
    linked_list_t *keys = ht_get_all_keys(graph->ip2node_ht);
    size_t keys_len = list_count(keys);
    size_t i;
    for (i = 0; i < keys_len; i++)
    {
        hashtable_key_t *keys_item = list_pick_value(keys, i);
        char ip[16] = {0};
        strncpy(ip, keys_item->data, keys_item->len);
        node_t *node = ht_get(graph->ip2node_ht, ip, strlen(ip), NULL);
        adj_ip_t *adj_ip_last = node->adj_ip_list;
        adj_ip_t *adj_ip_rover = adj_ip_last->next;
        while (adj_ip_rover != NULL)
        {
            adj_ip_t *next = adj_ip_rover->next;
            free(adj_ip_rover);
            adj_ip_last->next = next;
            if (next != NULL)
            {
                next->prev = adj_ip_last;
            }
            adj_ip_rover = next;
        }
        free(node);
    }
    list_destroy(keys);
    ht_destroy(graph->ip2node_ht);
    free(graph);
    return;
}

void update_graph(graph_t *graph, lsa_msg_t *lsa_msg)
{
    int8_t ret = 0;
    hashtable_t *ip2node_ht = graph->ip2node_ht;
    char source[1024] = {0};
    strncpy(source, lsa_msg->ip, 1023);
    node_t *node = NULL;
    if (ht_exists(ip2node_ht, source, strlen(source)) == 1)
    {
        node = ht_get(ip2node_ht, source, strlen(source), NULL);
        if (node->max_seq > lsa_msg->seq)
        {
            return;
        }
        node->max_seq = lsa_msg->seq;
    }
    else
    {
        node = malloc(sizeof(node_t));
        memset(node, 0, sizeof(node_t));
        ret = ht_set(ip2node_ht, source, strlen(source), node,
                     sizeof(node_t *));
        graph->node_num++;
        if (ret < 0)
        {
            printf("Set new key faild\n");
            return;
        }
        strncpy(node->ip, lsa_msg->ip, 15);
        node->max_seq = lsa_msg->seq;
        node->adj_ip_list = malloc(sizeof(adj_ip_t));
        memset(node->adj_ip_list, 0, sizeof(adj_ip_t));
    }
    size_t i = 0;
    for (i = 0; i < lsa_msg->adj_num; i++)
    {
        // printf("lsa_msg->adj_ip[%ld]: %s\n", i, lsa_msg->adj_ip[i]);
        add_neighboor(graph, node->adj_ip_list, source,
                      lsa_msg->adj_ip[i], lsa_msg->seq);
    }

    return;
}

void add_neighboor(graph_t *graph, adj_ip_t *adj_ip_list,
                   char *source, char *ip, size_t max_seq)
{
    hashtable_t *ip2node_ht = graph->ip2node_ht;
    adj_ip_t *adj_ip = n_exists(adj_ip_list, ip);
    int8_t ret = 0;
    if (adj_ip != NULL)
    {
        adj_ip->weight = 1;
    }
    else
    {
        adj_ip_t *next = malloc(sizeof(adj_ip_t));
        memset(next, 0, sizeof(adj_ip_t));
        next->next = adj_ip_list->next;
        adj_ip_list->next = next;

        strncpy(next->ip, ip, 15);
        next->weight = 1;
    }

    if (ht_exists(ip2node_ht, ip, strlen(ip)) == 1)
    {
        node_t *neighboor_node = ht_get(ip2node_ht, ip, strlen(ip), NULL);
        adj_ip_t *neig_adj_ip = n_exists(neighboor_node->adj_ip_list, source);
        if (neig_adj_ip != NULL)
        {
            neig_adj_ip->weight = 1;
        }
        else
        {
            adj_ip_t *next = malloc(sizeof(adj_ip_t));
            memset(next, 0, sizeof(adj_ip_t));
            next->next = neighboor_node->adj_ip_list->next;
            neighboor_node->adj_ip_list->next = next;

            strncpy(next->ip, source, 15);
            next->weight = 1;
        }
    }
    else
    {
        node_t *node = malloc(sizeof(node_t));
        memset(node, 0, sizeof(node_t));
        ret = ht_set(ip2node_ht, ip, strlen(ip), node, sizeof(node_t *));
        if (ret < 0)
        {
            printf("Set new key faild\n");
            return;
        }
        strncpy(node->ip, ip, 15);
        node->max_seq = max_seq;
        node->adj_ip_list = malloc(sizeof(adj_ip_t));

        memset(node->adj_ip_list, 0, sizeof(adj_ip_t));
        node->adj_ip_list->next = malloc(sizeof(adj_ip_t));
        memset(node->adj_ip_list->next, 0, sizeof(adj_ip_t));
        node->adj_ip_list->next->prev = node->adj_ip_list;
        node->adj_ip_list->next->next = NULL;

        strncpy(node->adj_ip_list->next->ip, source, 15);
        node->adj_ip_list->next->weight = 1;
        graph->node_num++;
    }

    return;
}

adj_ip_t *n_exists(adj_ip_t *adj_ip_list, char *ip)
{
    adj_ip_t *rover = adj_ip_list->next;
    while (rover != NULL)
    {
        if (strncmp(rover->ip, ip, 15) == 0)
        {
            return rover;
        }
        rover = rover->next;
    }

    return NULL;
}

void parse_lsa_line(lsa_msg_t *lsa_msg, char *line)
{
    memset(lsa_msg, 0, sizeof(lsa_msg_t));
    char adj_string[1024] = {0};
    sscanf(line, "%s %ld %s\n", lsa_msg->ip, &lsa_msg->seq, adj_string);

    // printf("adj_string: %s\n", adj_string);

    char *comma_ptr = NULL;
    char *start_ptr = adj_string;
    uint16_t read_len = 0;
    size_t index = 0;
    while (start_ptr != NULL)
    {
        comma_ptr = strstr(start_ptr, ",");
        if (comma_ptr == NULL)
        {
            read_len = strlen(start_ptr);
        }
        else
        {
            read_len = comma_ptr - start_ptr;
        }
        // printf("start_ptr: %s\n", start_ptr);
        strncpy(lsa_msg->adj_ip[index], start_ptr, read_len);
        // printf("lsa_msg->adj_ip[index]: %s\n", lsa_msg->adj_ip[index]);
        if (comma_ptr == NULL)
        {
            start_ptr = NULL;
        }
        else
        {
            start_ptr = comma_ptr + 1;
        }
        index++;
    }
    lsa_msg->adj_num = index;
    return;
}

adj_ip_t *find_last_adj_ip(node_t *node)
{
    adj_ip_t *rover = node->adj_ip_list;
    while (rover->next != NULL)
    {
        rover = rover->next;
    }

    return rover;
}

void print_lsa_msg(lsa_msg_t *lsa_msg)
{
    printf("source: %s\n", lsa_msg->ip);
    printf("seq: %ld\n", lsa_msg->seq);
    printf("adj:\n");
    size_t i = 0;
    for (i = 0; i < lsa_msg->adj_num; i++)
    {
        printf("%s\n", lsa_msg->adj_ip[i]);
    }

    return;
}

void print_graph(graph_t *graph)
{
    printf("-------print_graph begins------\n");
    linked_list_t *keys = ht_get_all_keys(graph->ip2node_ht);
    size_t keys_len = list_count(keys);
    size_t i;
    printf("node_num: %ld\n", graph->node_num);
    for (i = 0; i < keys_len; i++)
    {
        hashtable_key_t *keys_item = list_pick_value(keys, i);
        char ip[16] = {0};
        strncpy(ip, keys_item->data, keys_item->len);
        printf("\nip: %s\n", ip);
        node_t *node = ht_get(graph->ip2node_ht, ip, strlen(ip), NULL);
        printf("node ip: %s\n", node->ip);
        printf("node max_seq: %ld\n", node->max_seq);
        printf("node neighboors:\n");
        adj_ip_t *adj_ip_rover = node->adj_ip_list->next;
        while (adj_ip_rover != NULL)
        {
            printf("%s\n", adj_ip_rover->ip);
            adj_ip_rover = adj_ip_rover->next;
        }
    }
    list_destroy(keys);
    printf("-------print_graph ends------\n");
    return;
}

void print_s_ip_array(char s_ip_array[1024][1024], size_t s_num)
{
    printf("---print_s_ip_array begins---\n");
    size_t i = 0;
    for (i = 0; i < s_num; i++)
    {
        printf("%s\n", s_ip_array[i]);
    }
    printf("---print_s_ip_array ends---\n");
}