/*Constant definition*/
#define BUF_SIZE 65536
#define MAXLINE 4096
#define LISTENQ 1024  // The max number of fd that a process can create 
#define REQ_BUF_SIZE 8192  // Buffer that is used to save un-complete request
#define SKT_READ_BUF_SIZE 8192  // The max number of bytes read from client
#define S_SELT_TIMEOUT 0  // Time out value for select
#define US_SELT_TIMEOUT 1000
#define SUCCESS 0  //  Used by parser.y
#define MAX_SIZE 4096  // the max size for request headers that is longer
#define MAX_SIZE_S 64  // the max size for request headers that is smaller
#define MAX_TEXT 8192
#define MAX_MSG 65536
#define MAX_CGI_MSG 65536  // Max size of message read from CGI program
#define TYPE_SIZE 5  // The number of content-type that server supports
#define ENVP_len 23  // The number of arguments needed by CGI program
#define SCRIPT_NAME "/cgi"
#define MAX_CGI_ITER_COUNT 10  // The max times of read from CGI at once
#define MAX_READ_ITER_COUNT 10 // The max times of read data from any fd
#define MAX_WRIT_ITER_COUNT 10
#define S2C_DATA_SIZE 8192