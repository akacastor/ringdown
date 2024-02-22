#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h> 
#include <pthread.h>
#include <sys/stat.h>

#include "log.h"


pthread_mutex_t *log_mutex = NULL;


int global_log_level = LOG_INFO;

FILE *logfile;
char logfilename[MAX_LOGFILENAME_LEN] = {0};


// pass NULL to re-open 
int open_log(const char *filename)
{
    if( !log_mutex )
    {
        log_mutex = (pthread_mutex_t *)calloc(1,sizeof(pthread_mutex_t));
        if( !log_mutex )
        {
            printf( "error allocating memory for log_mutex!\n" );
            return -1;
        }
        pthread_mutex_init(log_mutex, NULL);
    }
    pthread_mutex_lock(log_mutex);

    if( filename )
    {
        strncpy( logfilename, filename, MAX_LOGFILENAME_LEN );
        logfilename[MAX_LOGFILENAME_LEN-1] = '\0';
    }
    
    if( logfile )
        fclose(logfile);
    logfile = fopen(logfilename,"at");

    pthread_mutex_unlock(log_mutex);

    if( !logfile )
        return -1;
   
    return 0;
}


void close_log(void)
{
    if( logfile )
        fclose(logfile);

    logfile = NULL;

    if( log_mutex )
    {
        pthread_mutex_destroy(log_mutex);
        log_mutex = NULL;
    }
}


int flog( int msg_log_level, const char *msg, ... )
{
    va_list argp;
    time_t ticks; 
    char log_str[4096] = "";
    struct stat fstat_buf;


    memset(&fstat_buf,0,sizeof(struct stat));
    
    if( logfile )
    {
        fstat(fileno(logfile), &fstat_buf );
    }

    // check if logfile is closed or if it has been deleted while open (st_nlink==0)
    if( !logfile || (fstat_buf.st_nlink < 1) )
    {
        open_log(NULL);
        if( !logfile )
            return -1;
    }

    if( msg_log_level <= global_log_level )
    {
        va_start( argp, msg );

        pthread_mutex_lock(log_mutex);
        ticks = time(NULL);

        snprintf( log_str, sizeof(log_str), "%.24s ", ctime(&ticks) );        
        if( msg )
            vsnprintf( log_str+strlen(log_str), sizeof(log_str)-strlen(log_str), msg, argp );

        if( !msg || !strlen(msg) || msg[strlen(msg)-1] != '\n' )
        {
            fprintf( logfile, "%s\n", log_str );
            printf( "%s\n", log_str );
        }
        fflush( logfile );
        pthread_mutex_unlock(log_mutex);

        va_end(argp);
    }


    return 0;
}
