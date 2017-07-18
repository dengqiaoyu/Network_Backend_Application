/******************************************************************************
 *                                 Video CDN                                  *
 *                          15-641 Computer Network                           *
 *                                dijstra.h                                   *
 * This file contains header file for dijstra.c                               *
 * Author: Qiaoyu Deng; Yangmei Lin                                           *
 * Andrew ID: qdeng; yangmeil                                                 *
 ******************************************************************************/

#ifndef DIJKSTRA_H
#define DIJKSTRA_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "graph.h"
#include "hashtable.h"

#define MAX_LINE 1024
#define MAX_S_NUM 1024

typedef struct shortest_path_s
{
  char ip[16];
  size_t dist;
  char path[65536];
  uint8_t is_fixed;
} shortest_path_t;

void dijkstra(graph_t *graph, hashtable_t *c2s_ip_ht,
              char s_ip_array[MAX_S_NUM][MAX_LINE], size_t s_num);
void find_fixed(hashtable_t *shortest_path_ht, char *next_hop,
                size_t *next_hop_dist, char *current_path);
char *find_best_server(hashtable_t *shortest_path_ht,
                       char s_ip_array[MAX_S_NUM][MAX_LINE],
                       size_t *hit_time_array, size_t s_num);
size_t get_hit_time_index(char s_ip_array[MAX_S_NUM][MAX_LINE], size_t s_num,
                          char *best_server_ip);
uint8_t is_server(char *s_ip, char s_ip_array[MAX_S_NUM][MAX_LINE],
                  size_t s_num);
void destroy_shortest_path_ht(hashtable_t *shortest_path_ht);
void print_shortest_path_ht(hashtable_t *shortest_path_ht);
void print_hit_time_array(char s_ip_array[MAX_S_NUM][MAX_LINE],
                          size_t *hit_time_array, size_t s_num);
void print_c2s_ip_ht(hashtable_t *c2s_ip_ht);
#endif