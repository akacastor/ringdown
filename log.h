#ifndef _LOG_H
#define _LOG_H


#define LOG_FATAL    (1)
#define LOG_ERROR    (2)
#define LOG_WARN     (3)
#define LOG_INFO     (4)
#define LOG_DEBUG    (5)

extern int global_log_level;

#define MAX_LOGFILENAME_LEN     1024
extern char logfilename[MAX_LOGFILENAME_LEN];


// pass NULL to re-open 
int open_log(const char *filename);

void close_log(void);


int flog( int msg_log_level, const char *msg, ... );


#endif  // _LOG_H
