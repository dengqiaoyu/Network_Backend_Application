#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "dijkstra.h"
#include "graph.h"
#include "hashtable.h"

void dijkstra(graph_t *graph, hashtable_t *c2s_ip_ht,
              char s_ip_array[MAX_S_NUM][MAX_LINE], size_t s_num)
{
    size_t *hit_time_array = malloc(sizeof(size_t) * s_num);
    memset(hit_time_array, 0 , sizeof(size_t) * s_num);
    linked_list_t *keys = ht_get_all_keys(graph->ip2node_ht);
    size_t keys_len = list_count(keys);
    size_t i;
    for (i = 0; i < keys_len; i++)
    {
        // printf("line 19 i: %zu\n", i);
        hashtable_key_t *keys_item = list_pick_value(keys, i);

        char client_ip[16] = {0};
        strncpy(client_ip, keys_item->data, keys_item->len);
        if (is_server(client_ip, s_ip_array, s_num) == 1)
        {
            continue;
        }
        hashtable_t *shortest_path_ht = ht_create(0, 1024, NULL);
        char next_hop[16] = {0};
        size_t next_hop_dist = 0;
        char current_path[65536] = {0};
        strncpy(next_hop, client_ip, 15);
        strncpy(current_path, next_hop, 15);
        // printf("next_hop: %s\n", next_hop);
        // printf("line 39 i: %zu\n", i);
        // if (i == 3)
        // {
        //     printf("error!\n");
        //     exit(1);
        // }
        size_t tmp_i = 0;
        while (next_hop[0] != 0)
        {
            tmp_i++;
            node_t *hop_node = ht_get(graph->ip2node_ht,
                                      next_hop, strlen(next_hop), NULL);
            adj_ip_t *adj_node_list = hop_node->adj_ip_list->next;
            adj_ip_t *adj_node_rover = adj_node_list;
            size_t tmp_j = 0;
            while (adj_node_rover != NULL)
            {
                tmp_j++;
                size_t dist = 0;
                char neighboor_ip[16] = {0};
                strncpy(neighboor_ip, adj_node_rover->ip, 15);
                // printf("neighboor_ip: %s\n", neighboor_ip);
                // if (tmp_i == 2 && tmp_j == 2)
                // {
                //     printf("neighboor_ip: %s\n", neighboor_ip);
                //     exit(1);
                // }
                if (strncmp(neighboor_ip, client_ip, 15) == 0)
                {
                    adj_node_rover = adj_node_rover->next;
                    continue;
                }
                dist = next_hop_dist + adj_node_rover->weight;
                // if (tmp_i == 2 && tmp_j == 2)
                // {
                //     printf("current_path: %s\n", current_path);
                //     printf("neighboor_ip: %s\n", neighboor_ip);
                //     printf("dist: %ld\n", dist);
                //     exit(1);
                // }
                if (ht_exists(shortest_path_ht, neighboor_ip, strlen(neighboor_ip)) == 0)
                {
                    shortest_path_t *shortest_path =
                        malloc(sizeof(shortest_path_t));
                    memset(shortest_path, 0, sizeof(shortest_path_t));
                    strncpy(shortest_path->ip, neighboor_ip,
                            strlen(neighboor_ip));
                    shortest_path->dist = dist;
                    shortest_path->is_fixed = 0;
                    snprintf(shortest_path->path, 65535, "%s->%s",
                             current_path, neighboor_ip);
                    ht_set(shortest_path_ht, neighboor_ip, strlen(neighboor_ip),
                           shortest_path, sizeof(shortest_path_t *));
                    // if (tmp_i == 2 && tmp_j == 2)
                    // {
                    //     print_shortest_path_ht(shortest_path_ht);
                    //     exit(1);
                    // }
                }
                else
                {
                    shortest_path_t *shortest_path = ht_get(shortest_path_ht,
                                                            neighboor_ip,
                                                            strlen(neighboor_ip), NULL);
                    if (shortest_path->dist > dist)
                    {
                        snprintf(shortest_path->path, 65535, "%s->%s",
                                 current_path, neighboor_ip);
                        shortest_path->dist = dist;
                    }
                }
                adj_node_rover = adj_node_rover->next;
            }
            // print_shortest_path_ht(shortest_path_ht);
            find_fixed(shortest_path_ht, next_hop, &next_hop_dist,
                       current_path);
            // printf("next_hop: %s\n", next_hop);
            // printf("next_hop_dist: %zu\n", next_hop_dist);
            // printf("current_path: %s\n", current_path);
            // print_shortest_path_ht(shortest_path_ht);
        }
        char *server_ip_ptr = NULL;
        char server_ip[1024] = {0};
        server_ip_ptr = find_best_server(shortest_path_ht, s_ip_array, hit_time_array, s_num);
        strncpy(server_ip, server_ip_ptr, 1023);
        // if (i == 1)
        // {
        //     printf("server_ip: %s\n", server_ip);
        //     print_hit_time_array(s_ip_array, hit_time_array, s_num);
        //     exit(1);
        // }
        ht_set_copy(c2s_ip_ht, client_ip, strlen(client_ip),
                    server_ip, strlen(server_ip), NULL, NULL);
        destroy_shortest_path_ht(shortest_path_ht);
    }
    free(hit_time_array);
    return;
}

void find_fixed(hashtable_t *shortest_path_ht, char *next_hop,
                size_t *next_hop_dist, char *current_path)
{
    linked_list_t *shortest_path_keys = ht_get_all_keys(shortest_path_ht);
    size_t len = list_count(shortest_path_keys);
    memset(next_hop, 0, 16);
    memset(current_path, 0, 65536);
    *next_hop_dist = ULONG_MAX;
    size_t i = 0;
    shortest_path_t *next_shortest_path = NULL;
    for (i = 0; i < len; i++)
    {
        char hop_ip[1024] = {0};
        hashtable_key_t *shortest_path_item =
            list_pick_value(shortest_path_keys, i);
        strncpy(hop_ip, shortest_path_item->data, shortest_path_item->len);
        shortest_path_t *shortest_path = ht_get(shortest_path_ht,
                                                hop_ip, strlen(hop_ip), NULL);
        if (shortest_path->is_fixed == 1)
        {
            continue;
        }
        if (shortest_path->dist < *next_hop_dist)
        {
            *next_hop_dist = shortest_path->dist;
            strncpy(next_hop, shortest_path->ip, 16);
            strncpy(current_path, shortest_path->path, 65535);
            next_shortest_path = shortest_path;
        }
    }

    if (next_shortest_path != NULL)
    {
        next_shortest_path->is_fixed = 1;
    }
    list_destroy(shortest_path_keys);
    return;
}

char *find_best_server(hashtable_t *shortest_path_ht,
                       char s_ip_array[MAX_S_NUM][MAX_LINE],
                       size_t *hit_time_array, size_t s_num)
{
    linked_list_t *shortest_path_keys = ht_get_all_keys(shortest_path_ht);
    size_t len = list_count(shortest_path_keys);
    char *best_server_ip = NULL;
    size_t min_dist = ULONG_MAX;
    size_t best_server_index = 0;
    size_t i = 0;
    for (i = 0; i < len; i++)
    {
        char dest_ip[1024] = {0};
        hashtable_key_t *shortest_path_item =
            list_pick_value(shortest_path_keys, i);
        strncpy(dest_ip, shortest_path_item->data, shortest_path_item->len);
        if (is_server(dest_ip, s_ip_array, s_num) != 1)
        {
            continue;
        }
        shortest_path_t *shortest_path = ht_get(shortest_path_ht,
                                                dest_ip, strlen(dest_ip), NULL);
        if (min_dist > shortest_path->dist)
        {
            best_server_ip = shortest_path->ip;
            min_dist = shortest_path->dist;
            size_t hit_time_index = get_hit_time_index(s_ip_array, s_num,
                                    best_server_ip);
            best_server_index = hit_time_index;
        }
        else if (min_dist == shortest_path->dist)
        {
            size_t min_dist_hit_time_index = get_hit_time_index(s_ip_array,
                                             s_num, best_server_ip);
            size_t hit_time_index = get_hit_time_index(s_ip_array, s_num,
                                    shortest_path->ip);
            if (hit_time_array[min_dist_hit_time_index] > hit_time_array[hit_time_index])
            {
                best_server_ip = shortest_path->ip;
                min_dist = shortest_path->dist;
                best_server_index = hit_time_index;
            }
        }
    }
    hit_time_array[best_server_index]++;

    return best_server_ip;
}

size_t get_hit_time_index(char s_ip_array[MAX_S_NUM][MAX_LINE], size_t s_num,
                          char *best_server_ip)
{
    size_t i = 0;
    for (i = 0; i < s_num; i++)
    {
        if (strncmp(best_server_ip, s_ip_array[i], 15) == 0)
        {
            break;
        }
    }

    return i;
}

uint8_t is_server(char *s_ip, char s_ip_array[MAX_S_NUM][MAX_LINE],
                  size_t s_num)
{
    size_t i = 0;
    for (i = 0; i < s_num; i++)
    {
        if (strncmp(s_ip, s_ip_array[i], 15) == 0)
        {
            return 1;
        }
    }
    return 0;
}

void destroy_shortest_path_ht(hashtable_t *shortest_path_ht)
{
    linked_list_t *shortest_path_keys =
        ht_get_all_keys(shortest_path_ht);
    size_t len = list_count(shortest_path_keys);
    size_t i = 0;
    for (i = 0; i < len; i++)
    {
        char ip[1024] = {0};
        hashtable_key_t *shortest_path_item =
            list_pick_value(shortest_path_keys, i);
        strncpy(ip, shortest_path_item->data, shortest_path_item->len);
        shortest_path_t *shortest_path = ht_get(shortest_path_ht,
                                                ip, strlen(ip), NULL);
        free(shortest_path);
    }
    ht_destroy(shortest_path_ht);
}

void print_shortest_path_ht(hashtable_t *shortest_path_ht)
{
    printf("-------print_shortest_path_ht begins------\n");
    linked_list_t *shortest_path_keys = ht_get_all_keys(shortest_path_ht);
    size_t len = list_count(shortest_path_keys);
    size_t i = 0;
    for (i = 0; i < len; i++)
    {
        char ip[1024] = {0};
        hashtable_key_t *shortest_path_item =
            list_pick_value(shortest_path_keys, i);
        strncpy(ip, shortest_path_item->data, shortest_path_item->len);
        shortest_path_t *shortest_path = ht_get(shortest_path_ht,
                                                ip, strlen(ip), NULL);
        printf("ip: %s\n", shortest_path->ip);
        printf("dist: %ld\n", shortest_path->dist);
        printf("path: %s\n", shortest_path->path);
        printf("is_fixed: %d\n\n", shortest_path->is_fixed);
    }
    printf("-------print_shortest_path_ht ends------\n");

    return;
}

void print_hit_time_array(char s_ip_array[MAX_S_NUM][MAX_LINE],
                          size_t *hit_time_array, size_t s_num)
{
    size_t i = 0;
    printf("-------print_hit_time_array begins------\n");
    for (i = 0; i < s_num; i ++)
    {
        printf("%s, %zu\n", s_ip_array[i], hit_time_array[i]);
    }
    printf("-------print_hit_time_array ends------\n");
    return;
}

void print_c2s_ip_ht(hashtable_t *c2s_ip_ht)
{
    printf("-------print_c2s_ip_ht begins------\n");
    linked_list_t *c2s_ip_keys = ht_get_all_keys(c2s_ip_ht);
    size_t len = list_count(c2s_ip_keys);
    size_t i = 0;
    for (i = 0; i < len; i++)
    {
        char client_ip[1024] = {0};
        hashtable_key_t *c2s_ip_item =
            list_pick_value(c2s_ip_keys, i);
        strncpy(client_ip, c2s_ip_item->data, c2s_ip_item->len);
        char *server_ip = ht_get(c2s_ip_ht,
                                 client_ip, strlen(client_ip),
                                 NULL);
        printf("%s-->%s\n", client_ip, server_ip);
    }
    printf("-------print_c2s_ip_ht ends------\n");

    return;
}