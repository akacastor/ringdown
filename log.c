#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h> 
#include <pthread.h>

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
        if( log_mutex )
            pthread_mutex_init(log_mutex, NULL);
    }
    

    if( filename )
    {
        strncpy( logfilename, filename, MAX_LOGFILENAME_LEN );
        logfilename[MAX_LOGFILENAME_LEN-1] = '\0';
    }
    
    if( logfile )
        fclose(logfile);
    logfile = fopen(logfilename,"at");

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
    int try_count=3;
    time_t ticks; 
    char log_str[4096] = "";


    if( !logfile )
    {
        open_log(NULL);
        if( !logfile )
            return -1;
    }

    va_start( argp, msg );

    if( msg_log_level >= global_log_level )
    {
        pthread_mutex_lock(log_mutex);
        ticks = time(NULL);

        do
        {
            if( fprintf( logfile, "%.24s ", ctime(&ticks) ) > 0 )
                break;
            open_log(NULL);     // error occured, try re-opening logfile
        }while(--try_count);
        
        printf( "%.24s ", ctime(&ticks) );
        
        if( try_count == 0 )
        {
            va_end(argp);
            return -1;
        }
        
        if( msg )
        {
            if( vsnprintf( log_str, sizeof(log_str), msg, argp ) < 0 )
            {
                va_end(argp);
                return -2;
            }
            vprintf( msg, argp );
        }

        if( !msg || !strlen(msg) || msg[strlen(msg)-1] != '\n' )
        {
            fprintf( logfile, "%s\n", log_str );
            printf( "%s\n", log_str );
        }
        fflush( logfile );
        pthread_mutex_unlock(log_mutex);
    }

    va_end(argp);

    

    return 0;
}
