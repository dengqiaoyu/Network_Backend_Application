#include "parse_manifest.h"

char * get_f4m_content(pools_t *p, int clientfd)
{
	char *f4m_content = NULL;
	s2c_data_list_t *send2s_req_start = p->s2c_list[clientfd];
    s2c_data_list_t *rover = send2s_req_start->next;
	char *p1 = NULL;
	int f4m_len = 0;
	int f4m_strlen = BUF_SIZE;
	int flag = 0;
    while(rover!=NULL)
    {
    	p1 = strstr(rover->data,"\r\n\r\n");
    	if(p1!=NULL)
    	{
    		p1+=4;
    		f4m_content = malloc(f4m_strlen*sizeof(char));
    		strncpy(f4m_content,p1,strlen(p1));
    		f4m_len = strlen(p1);
    		rover = rover->next;
    		flag = 1;
    		break;
    	}
    }
    while(flag == 1 && rover!=NULL)
    {
    	if(f4m_strlen - f4m_len< rover->len)
    	{
    		f4m_strlen = f4m_strlen+BUF_SIZE*2;
    		f4m_content = realloc(f4m_content, f4m_strlen*sizeof(char));
    	}
    	strncpy(f4m_content, rover->data, rover->len);
    	f4m_len += rover->len;
    	rover = rover->next;
    }

    //send2s_req_start = p->s2c_list[clientfd];
    rover = send2s_req_start->next;
    int j = 0;
    while(rover!=NULL)
    {
    	send2s_req_start->next = rover->next;
        free(rover);
        rover = send2s_req_start->next;
	j++;
	//printf("j:%d\n",j);
    }
    //printf("free succeed\n");
    return f4m_content;
	
}
bitrate_t * parse_manifest(char *mani_file)
{
	int i = 0;
	char *mark = "bitrate=";
	char *p = NULL;
	bitrate_t * result_manifest = malloc(sizeof(bitrate_t));
	memset(result_manifest,0,sizeof(bitrate_t));
	int n = 0;
	char * mani_temp = mani_file;
	while(1)
	{
		p = strstr(mani_temp, mark);
		if(p!=NULL)
		{
			char bitrate[10] = {0};
			p+=strlen(mark);
			for(i = 1; p[i]!='"'; i++)
			{
				bitrate[i-1] = p[i];
			}
			result_manifest->bitrate[n] = (int)(atoi(bitrate));
			// printf("bitrate: %d\n", result_manifest->bitrate[n]);
			n++;
			mani_temp = p+i;
			

		}
		else
		{
			result_manifest->bitrate_num = n;
			dbg_cp3_d2_printf("---------- .f4m result ---------\n");
			for(i = 0; i< result_manifest->bitrate_num; i++)
		    {
		    	dbg_cp3_d2_printf("bitrate[%d]: %d\n",i, \
		    		result_manifest->bitrate[i]);
		    }
		    dbg_cp3_d2_printf("-----------   end   ---------\n");
			return result_manifest;
		}
	}
}

// int main()
// {
// 	FILE* file = fopen("big_buck_bunny.f4m","r");
//     if(file == NULL)
//     {
//         return -1;
//     }

//     fseek(file, 0, SEEK_END);
//     long int size = ftell(file);
//     rewind(file);

//     char* content = calloc(size + 1, 1);
//     fread(content,1,size,file);
//     // printf("%s\n",content);
//     bitrate_t * mani_p = parse_manifest(content);
//     int i = 0;
//     printf("bitrate_num:%d\n", mani_p->bitrate_num);
//     for(i = 0; i< mani_p->bitrate_num; i++)
//     {
//     	printf("bitrate[%d]: %d\n",i,mani_p->bitrate[i]);
//     }


//     return 0;
// }
