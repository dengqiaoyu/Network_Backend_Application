#include <stdlib.h>
#include <stdio.h>
#include "proxy.h"

/**
 * Initiate pool for read&write select
 * @param listenfd     http fd
 * @param p            pool that needs to be initiated
 */
void init_pool(int listenfd, pools_t *p) {
    size_t i;

    FD_ZERO(&p->active_rd_set);
    FD_ZERO(&p->active_wt_set);
    FD_ZERO(&p->ready_rd_set);
    FD_ZERO(&p->ready_wt_set);
    p->num_ready = 0;
    FD_SET(listenfd, &p->active_rd_set);
    for (i = 0; i < FD_SETSIZE; i++) {
        p->clientfd[i] = -1;
        p->serverfd[i] = -1;
        p->ign_first[i] = 0;
        p->too_long[i] = 0;
        p->close_fin[i] = 0;
        memset(p->cached_buf[i], 0, REQ_BUF_SIZE + 1);
        p->cached_req[i] = NULL;
        // The first item of list is never used but used as a start point
        memset(p->clientip[i], 0, 16);
        memset(p->serverip[i], 0, 16);
        p->fd_c2s[i] = -1;
        p->fd_s2c[i] = -1;
        p->send2s_list[i] = malloc(sizeof(send2s_req_t));
        memset(p->send2s_list[i], 0 , sizeof(send2s_req_t));
        p->s2c_list[i] = malloc(sizeof(s2c_data_list_t));
        memset(p->s2c_list[i], 0 , sizeof(s2c_data_list_t));
        p->log_rec_list[i] = malloc(sizeof(log_record_t));
        memset(p->log_rec_list[i], 0, sizeof(log_record_t));
        p->pack_len[i] = 0;
        p->frag_len[i] = 0;

        
    }
    p->mani_info = init_manifest();
    p->thr_info = init_throughput();
    p->ip2mani_ht = NULL;
    p->ip2thr_ht = NULL;

    
}

manifest_t * init_manifest()
{
    manifest_t *mani = malloc(sizeof(manifest_t));
    memset(mani,0,sizeof(manifest_t));
    size_t i;
    for (i = 0; i < FD_SETSIZE; i++) {
        mani->flag_send_f4m[i] = 0;
        mani->f4m_req[i] = NULL;
        mani->bitrate_rec[i] = NULL;
        
    }
    return mani;
}

throughput_t * init_throughput()
{
    throughput_t * thr_info = malloc(sizeof(throughput_t));
    memset(thr_info,0,sizeof(throughput_t));
    size_t i;
    struct timeval now;
    gettimeofday(&now,NULL);
    for (i = 0; i < FD_SETSIZE; i++) {

        thr_info->ts_rec[i] = now;
        //thr_info->thr_cur[i] = 1000;
        thr_info->thr_cur[i] = 0;
        thr_info->send_fra_req[i] = 0;
    }
    return thr_info;
}

/**
 * Add client to the read&write pool
 * @param  connfd the fd of client
 * @param  p      pool
 * @param  c_host IP of client
 * @return        -1 for fail, 0 for success
 */
ssize_t add_client(int connfd, pools_t *p, char *c_host)
{
    p->num_ready--;
    fcntl(connfd, F_SETFL, O_NONBLOCK);
    p->clientfd[connfd] = 1;
    FD_SET(connfd, &p->active_rd_set);
    FD_SET(connfd, &p->ready_rd_set);
    dbg_cp3_p3_printf("add client: %d\n", connfd);
    strncpy(p->clientip[connfd], c_host, MAX_SIZE_S);
    return 0;
}
