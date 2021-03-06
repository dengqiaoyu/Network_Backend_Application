/******************************************************************************
 *                                 Video CDN                                  *
 *                          15-641 Computer Network                           *
 *                                 throughput.c                               *
 * This file contains the implementation of all the functions used in         *
 * computing throughput and writing to proxy.log.                             *
 * Author: Qiaoyu Deng; Yangmei Lin                                           *
 * Andrew ID: qdeng; yangmeil                                                 *
 ******************************************************************************/
#include "throughput.h"

extern FILE *log_pFile;

/**
 * This function chooses the bitrate for a video fragment
 * @return  chosen bitrate
 */
int get_new_bitrate(pools_t *p, int clientfd)
{
    char ip_str[16] = {0};
    strncpy(ip_str, &(p->clientip[clientfd][0]), 15);
    double * thr_cur_p = NULL;
    thr_cur_p = ht_get(p->ip2thr_ht, ip_str, 15, NULL);
    if (thr_cur_p == NULL)
    {
        printf("thr_cur in hashtalbe of %s is NULL\n", ip_str);
        exit(-1);
    }
    double thr_cur = *thr_cur_p;
    bitrate_t *bit_p =  p->mani_info->bitrate_rec[clientfd];
    if (bit_p == NULL)
    {
        bit_p = ht_get(p->ip2mani_ht, ip_str, 15, NULL);
        if (bit_p == NULL)
        {
            printf(" !!! Does not find manifest by ip! \n");
            exit(0);
        }
    }

    int bitrate_n = bit_p->bitrate_num;
    int *bitrate_list = bit_p->bitrate;
    if (bitrate_list == NULL)
    {
        return 500;
    }
    int i = 0;
    for (i = bitrate_n - 1; i >= 0; i--)
    {
        if (thr_cur > bitrate_list[i] * 1.5)
        {
            return bitrate_list[i];
        }
    }
    return bitrate_list[0];
}

/**
 * This function get the length of a recieved video fragment
 * @return length of the video fragment
 */
int get_frag_size(pools_t *p, int clientfd)
{
    s2c_data_list_t *send2s_req_start = p->s2c_list[clientfd];
    s2c_data_list_t *rover = send2s_req_start->next;
    char * p1 = NULL;
    int frag_len = 0;
    while (rover != NULL)
    {
        p1 = strstr(rover->data, "Content-Length");
        char len_str[20] = {0};
        int i = 0;
        if (p1 != NULL)
        {
            int m = 0;
            p1 += (strlen("Content-Length ") + 1);
            while (p1[0] >= '0' && p1[0] <= '9')
            {
                len_str[i] = p1[0];
                i++;
                p1++;
            }
            frag_len = atoi(len_str);
            break;
        }
        else
        {
            rover = rover->next;
        }
    }
    return frag_len;
}

/**
 * This function calculate the length of a packet sent by server
 * @return length of packet
 */
int get_package_size(pools_t *p, int clientfd, int frag_len)
{
    s2c_data_list_t *send2s_req_start = p->s2c_list[clientfd];
    s2c_data_list_t *rover = send2s_req_start->next;
    char * p1 = NULL;
    int package_len = 0;
    if (rover != NULL)
    {
        p1 = strstr(rover->data, "\r\n\r\n");
        if (p1 != NULL)
        {
            package_len = p1 - rover->data + frag_len + 4;
            return package_len;

        }
        else
        {
            exit(0);
        }
    }

}

/**
 * update the length of the part of a packet that is already recieved by proxy
 * @return the updated packet length
 */
int update_pack_recv_len(pools_t *p, int clientfd, int package_len)
{
    s2c_data_list_t *send2s_req_start = p->s2c_list[clientfd];
    s2c_data_list_t *rover = send2s_req_start->next;
    int result_len = package_len;
    while (rover != NULL)
    {
        result_len -= rover->len;
        rover = rover->next;
    }
    return result_len;
}

/**
 * This function calculate the current throughput of link between proxy and
 * server
 * @return Never returns
 */
void update_thr_cur(int frag_len, struct timeval tf, float alpha, \
                    throughput_t * thr_info, int clientfd, pools_t *p)
{
    struct timeval ts = thr_info->ts_rec[clientfd];
    int frag_len_in_bit = frag_len * 8;
    double diff_t = tf.tv_sec - ts.tv_sec + (tf.tv_usec - ts.tv_usec) / 1000000.0;
    double thr_new = ((double)(frag_len_in_bit)) / (diff_t * 1000);

    char ip_str[16] = {0};
    strncpy(ip_str, &(p->clientip[clientfd][0]), 15);
    double * thr_cur_p = NULL;
    thr_cur_p = ht_get(p->ip2thr_ht, ip_str, 15, NULL);
    if (thr_cur_p == NULL)
    {
        exit(-1);
    }
    double thr_cur = *thr_cur_p;

    thr_cur = alpha * thr_new + (1 - alpha) * thr_cur;
    int ret = ht_set_copy(p->ip2thr_ht, ip_str, 15, &thr_cur, \
                          sizeof(double), NULL, NULL);
    p->log_rec_list[clientfd]->duration = diff_t;
    p->log_rec_list[clientfd]->tput = thr_new;
    p->log_rec_list[clientfd]->avg_tput = thr_cur;
}

/**
 * Print one log record to proxy's log as required in handout
 * @return  Never returns
 */
void print_to_log(log_record_t * log_rec)
{
    fprintf(log_pFile, "%d ", (int)(log_rec->cur_time));
    fprintf(log_pFile, "%.6f ", log_rec->duration);
    fprintf(log_pFile, "%.2f ", log_rec->tput);
    fprintf(log_pFile, "%.2f ", log_rec->avg_tput);
    fprintf(log_pFile, "%d ", log_rec->req_bitrate);
    fprintf(log_pFile, "%s ", log_rec->server_ip);
    fprintf(log_pFile, "%s\n", log_rec->chunk_name);
    fflush(log_pFile);

}
