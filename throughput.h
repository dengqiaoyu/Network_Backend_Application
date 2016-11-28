#include "proxy.h"

int get_new_bitrate(pools_t *p, int clientfd);
int get_frag_size(pools_t *p, int clientfd);
void update_thr_cur(int frag_len, struct timeval tf,float alpha, \
	throughput_t * thr_info, int clientfd, pools_t *p);
void print_to_log(log_record_t * log_rec);
int get_package_size(pools_t *p, int clientfd, int frag_len);
int update_pack_recv_len(pools_t *p, int clientfd, int package_len);