// telnet ringdown - Chris Gerlinsky, 2024-02-22

//TODO - track traffic on each connection
//       display CPS for last 5 seconds?

//TODO - could fix dosbox broken telnet emulation for zmodem uploads?
//       how to detect this?  smart algorithm would identify zmodem downloads and the crc errors ?  (ambitious)

//TODO - detect when ringdown.ban has been updated and reload it from disk (to allow manually adding IPs to ban)


#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/time.h>
#include <signal.h>
#include <sys/stat.h>

#include "ringdown.h"
#include "log.h"
#include "conf.h"
#include "cbuf.h"


char log_filename[1024] = "ringdown.log";
char conf_filename[1024] = "ringdown.conf";
char ban_list_filename[1024] = "ringdown.ban";

time_t ban_list_mtime;          // last modification time of ban_list_filename


int default_connecttime = 5;    // 5 second timeout attempting to connect to each destaddr

struct _listenaddr *listenaddr = NULL;
int num_listenaddr = 0;

char failmsg_filename[1024] = {0};

int no_answer_time = 0;         // time (in seconds) after which we will disconnect from destaddr if they haven't sent any data yet

unsigned int escape_pre_time = 1000;    // time (in ms) that must be idle before +++ escape sequence
unsigned int escape_post_time = 1000;    // time (in ms) that must be idle after +++ escape sequence
char escape_seq_sourceip[1024] = "}}}SOURCEIP?";

struct _ip_ban *ban_list = NULL;
int num_ban_list = 0;
int ban_time = 0;                       // ban time in minutes (for first attempt, will be multiplied by ban_multiplier on subsequent bans)
int ban_multiplier = 0;                 // factor by which to increase ban time with each attempt
int max_ban_time = 0;                   // maximum length of a ban in minutes
char bannedmsg_filename[1024] = "";
int bot_detect_time = 0;                // how long to watch for suspicious login attempts, in seconds
char **bad_words = NULL;
int num_bad_words = 0;
int bot_sleep_time = 30;                // sleep() for 30 seconds before disconnecting bot (slow them down where we can)


pthread_mutex_t *ban_list_mutex = NULL;


struct _serve_client_args
{
    int srcfd;
    struct sockaddr_in address;

    int listen_idx;
    
    unsigned long bytes_rx;
    unsigned long bytes_tx;
};


void save_ban_list(char *filename)
{
    int i;
    FILE *ban_list_file;
    
    
    if( !filename )
        return;

    ban_list_file = fopen(filename, "wt");
    if( !ban_list_file )
    {
        flog( LOG_ERROR, "unable to open ban_list file: %s", filename );
        return;
    }
    
    for( i=0; i<num_ban_list; i++ )
        fprintf( ban_list_file, "%s %lu %d\n", inet_ntoa(ban_list[i].addr), ban_list[i].expire_time, ban_list[i].count );

    fclose( ban_list_file );

    
    return;
}


void restore_ban_list(char *ban_list_filename)
{
    FILE *ban_list_file;
    char line_str[1024];
    char *tok;
    char sep[]=" \t\r\n";
    struct in_addr addr;
    time_t expire_time;
    int count;
    int i;
    
    
    if( !ban_list_filename )
        return;

    ban_list_file = fopen(ban_list_filename, "rt");
    if( !ban_list_file )
    {
        flog( LOG_ERROR, "unable to open ban_list file: %s", ban_list_filename );
        return;
    }
    
    while( !feof(ban_list_file) && !ferror(ban_list_file) )
    {
        if( !fgets( line_str, sizeof(line_str), ban_list_file ) )
            break;
        
        tok = strtok( line_str, sep );
        if( !tok )
            continue;
            
        addr.s_addr = inet_addr( tok );

        tok = strtok( NULL, sep );
        if( !tok )
            continue;

        expire_time = strtoul( tok, NULL, 0 );
        
        tok = strtok( NULL, sep );
        if( !tok )
            continue;

        count = strtol( tok, NULL, 0 );

        if( addr.s_addr == 0 )
            continue;       // invalid IP address - not a valid ban line        
        

        for( i=0; i<num_ban_list; i++ )
        {
            if( addr.s_addr == ban_list[i].addr.s_addr )
                break;
        }
        if( i >= num_ban_list )
        {
            num_ban_list++;
            ban_list = (struct _ip_ban *)realloc(ban_list, sizeof(struct _ip_ban) * num_ban_list);
            if( !ban_list )
            {
                num_ban_list = 0;
                flog( LOG_ERROR, "unable to realloc ban_list" );
                break;
            }
            i = num_ban_list-1;
        }
        
        ban_list[i].addr = addr;
        ban_list[i].expire_time = expire_time;
        ban_list[i].count = count;
    }
    
    fclose( ban_list_file );

    
    return;
}


// returns # of minutes remaining in ban, or 0 if not banned
int check_banned( struct in_addr banaddr )
{
    int i;
    time_t ticks;
    int ban_time_remaining = 0;
    
    
    pthread_mutex_lock(ban_list_mutex);

    for( i=0; i<num_ban_list; i++ )
    {
        if( banaddr.s_addr == ban_list[i].addr.s_addr )
            break;
    }
    
    if( i < num_ban_list )
    {
        ticks = time(NULL);
        if( ban_list[i].expire_time > ticks )
            ban_time_remaining = (ban_list[i].expire_time - ticks) / 60;
    }

    pthread_mutex_unlock(ban_list_mutex);

    
    return ban_time_remaining;
}


// returns index into ban_list[] where banaddr is found, or -1 if not found
int check_ban_list( struct in_addr banaddr )
{
    int i;
    
    
    pthread_mutex_lock(ban_list_mutex);

    for( i=0; i<num_ban_list; i++ )
    {
        if( banaddr.s_addr == ban_list[i].addr.s_addr )
            break;
    }
    
    if( i >= num_ban_list )
        i = -1;
    
    pthread_mutex_unlock(ban_list_mutex);

    
    return i;
}


int add_to_ban_list( struct in_addr banaddr )
{
    int idx;
    int expire_time;
    struct stat fstat_buf;


    idx = check_ban_list(banaddr);
    pthread_mutex_lock(ban_list_mutex);
    if( idx == -1 )
    {   // not in list, we must add it
        num_ban_list++;
        ban_list = (struct _ip_ban *)realloc( ban_list, num_ban_list * sizeof(struct _ip_ban) );
        if( !ban_list )
        {
            flog( LOG_ERROR, "error allocating %d bytes for ban_list!", num_ban_list * sizeof(struct _ip_ban) );
            num_ban_list = 0;
            pthread_mutex_unlock(ban_list_mutex);
            return 0;
        }
        idx = num_ban_list - 1;
        memset( &ban_list[idx], 0, sizeof(struct _ip_ban) );
        ban_list[idx].addr = banaddr;
    }    

    ban_list[idx].count++;

    // calculate when ban should expire    
    expire_time = ban_time*60 * (ban_list[idx].count - 1) * ban_multiplier;
    if( !expire_time )
        expire_time = ban_time*60;

    if( max_ban_time && expire_time > max_ban_time )
        expire_time = max_ban_time;
        
    expire_time += time(NULL);

    if( expire_time > ban_list[idx].expire_time )
        ban_list[idx].expire_time = expire_time;
    
    // save the updated ban list to disk
    save_ban_list( ban_list_filename );
    memset( &fstat_buf, 0, sizeof(struct stat) );
    stat( ban_list_filename, &fstat_buf );
    ban_list_mtime = fstat_buf.st_mtime;    // update ban_list_mtime so we don't instantly reload it from disk

    pthread_mutex_unlock(ban_list_mutex);


    return 0;
}


void print_banned_msg( int srcfd, struct sockaddr_in srcaddress, int time_left )
{
    FILE *bannedmsg_file = NULL;
    int readbyte;
    char text[1024];
    
    
    if( strlen(bannedmsg_filename) && (bannedmsg_file = fopen( bannedmsg_filename, "rt" )) )
    {
        while( !feof(bannedmsg_file) && !ferror(bannedmsg_file) )
        {
            if( readbyte < 0 )
            {
                readbyte = fgetc(bannedmsg_file);
                if( feof(bannedmsg_file) || ferror(bannedmsg_file) )
                    break;
            }
            
            if( readbyte == '`' )
            {   // replace backtick ` with the # of minutes until ban is lifted
                snprintf( text, sizeof(text), "%d", 1+time_left );
                
                if( write( srcfd, text, strlen(text) ) < 1 )
                {
                    if( errno == EAGAIN || errno == EWOULDBLOCK )
                        continue;
                    else
                        break;  // disconnected
                }
            }            
            else if( write( srcfd, &readbyte, 1 ) < 0 )
            {
                if( errno == EAGAIN || errno == EWOULDBLOCK )
                    continue;
                else
                    break;  // disconnected
            }

            readbyte = -1;  // set readbyte to -1 so next byte will be read from file
        }
        
        fclose(bannedmsg_file);
        sleep(2);        // sleep so bannedmsg is sent before socket is closed
    }
}


void passthru_connection( int srcfd, struct sockaddr_in srcaddress, int destfd, struct in_addr destaddress, unsigned int destport, struct _serve_client_args *serve_client_args )
{
    int connected = 1;
    const int rxbuf_len = 1024;
    struct _cbuf srcrxbuf;
    struct _cbuf destrxbuf;
    const int txbuf_len = 1024;
    int n;
    char rxcharbuf[rxbuf_len];
    char txcharbuf[txbuf_len];
    int rx_pkt_size = 1;        // receive at most 1 byte at a time
    int tx_pkt_size = 1;        // send at most 1 byte at a time
    int processed_data;         // flag indicating if any data was processed this round through while() loop
    struct timeval last_data_timeval;
    struct timeval current_timeval;
    int escape_sequence;        // 0 = no escape sequence started, 1,2,3 = number of +, 4 = 1 second delay measured after +++ (complete)
    int i;
    char client_text[1024];     // data sent by client when first connected - used for detecting bots to apply bans
    int client_text_len = 0;
    time_t connect_start_time;
    int do_bot_detect = 1;
    char *str_ptr;
    char text_buf[1024];


    // initialize circular buffers to hold data being passed between src (client) and dest
    if( !InitCBuf( &srcrxbuf, rxbuf_len ) )
    {
        flog( LOG_ERROR, "unable to allocate srcrxbuf" );
        return;
    }
    if( !InitCBuf( &destrxbuf, rxbuf_len ) )
    {
        flog( LOG_ERROR, "unable to allocate destrxbuf" );
        FreeCBuf(&srcrxbuf);
        return;
    }
    
    memset( &last_data_timeval, 0, sizeof(struct timeval) );


    connect_start_time = time(NULL);
    while( connected )
    {
        processed_data = 0;
        
        // check for data from source
        n = read( srcfd, rxcharbuf, rx_pkt_size );
        if( n < 0 && !(errno == EAGAIN || errno == EWOULDBLOCK) )
            break;  // disconnected
        else if( n > 0 )
        {
            AddDataToCBuf( &srcrxbuf, (uint8_t *)rxcharbuf, n );
            serve_client_args->bytes_tx++;
            processed_data++;

            // bot detection - parse data received from client to look for brute-force login attempts like "root"
            if( do_bot_detect && time(NULL) - connect_start_time < bot_detect_time )
            {   // if we are still within bot_detect_time, keep a record of what is sent by client in client_text[]
                memcpy( client_text+client_text_len, rxcharbuf, client_text_len + n < sizeof(client_text) ? n : sizeof(client_text)-client_text_len );
                client_text_len += n;
                if( client_text_len > sizeof(client_text) )
                    client_text_len = sizeof(client_text);

                if( memchr( client_text, 0x1B, client_text_len ) )
                {   // Esc was received - users press this to enter BBS, disable bot detection after this point
                    do_bot_detect = 0;
                }
                else if( (str_ptr = memchr( client_text, '\r', client_text_len )) )
                {   // carriage return was received, was it a bot login attempt?
                    *str_ptr = '\0';    // replace carriage return with NULL
                    while( str_ptr > client_text )
                    {   // search for any non-printable characters received (such as telnet IAC responses)
                        str_ptr--;
                        if( str_ptr[0] <= 0x20 || str_ptr[0] >= 0x7F )
                            break;
                    }

                    if( str_ptr[0] <= 0x20 || str_ptr[0] >= 0x7F )
                        str_ptr++;  // skip the non-printable character

                    if( strlen(str_ptr) == 0 )
                        client_text_len = 0;        // we received a CR with nothing else, throw it away and keep watching
                    else
                    {   // check bad_words[] list to see if this is a known brute-force attempt
                        for( i=0; i<num_bad_words; i++ )
                        {
                            if( !strcasecmp( str_ptr, bad_words[i] ) )
                                break;
                        }
                        if( i<num_bad_words )
                        {   // found a match - ban this IP
                            close( destfd );
                            add_to_ban_list( srcaddress.sin_addr );
                            flog( LOG_INFO, "banned IP %s for %d minutes for login attempt '%s'", inet_ntoa(srcaddress.sin_addr), check_banned(srcaddress.sin_addr), str_ptr );
                            sleep( bot_sleep_time );
                            close( srcfd );
                            break;
                        }
                        else
                        {   // a word was entered, followed by CR, that isn't in bad_words[] list
                            flog( LOG_DEBUG, "login attempt from %s? '%s'", inet_ntoa(srcaddress.sin_addr), str_ptr );
                        }
                    }
                }
            }
            else
                do_bot_detect = 0;
        }
        else if( n == 0 )
            break;  // disconnected

        if( do_bot_detect && time(NULL) - connect_start_time >= bot_detect_time )
        {
            text_buf[0] = '\0';
            n = 0;
            for( i=0; i<client_text_len && n+1<sizeof(text_buf); i++ )
            {
                if( client_text[i] >= 0x20 && client_text[i] < 0x7F )
                {
                    if( n+1 >= sizeof(text_buf) )
                        break;
                    text_buf[n++] = client_text[i];
                    text_buf[n] = '\0';
                }
                else if( n+4 < sizeof(text_buf) )
                {
                    text_buf[n++] = '\\';
                    text_buf[n++] = 'x';
                    text_buf[n++] = (client_text[i]>>4) <= 9 ? '0' + (client_text[i]>>4) : 'A' + (client_text[i]>>4) - 0xA;
                    text_buf[n++] = (client_text[i]&0xF) <= 9 ? '0' + (client_text[i]&0xF) : 'A' + (client_text[i]&0xF) - 0xA;
                    text_buf[n] = '\0';
                }
            }
            flog( LOG_DEBUG, "bot_detect_time timed out with %d bytes received from client: '%s'", serve_client_args->bytes_tx, text_buf );
            do_bot_detect = 0;
        }

        // get timestamp of current time when checking for data from dest (used for escape sequence)
        gettimeofday( &current_timeval, NULL );

        // check for data from dest
        n = read( destfd, rxcharbuf, rx_pkt_size );
        if( n < 0 && !(errno == EAGAIN || errno == EWOULDBLOCK) )
            break;  // disconnected
        else if( n > 0 )
        {
            AddDataToCBuf( &destrxbuf, (uint8_t *)rxcharbuf, n );
            serve_client_args->bytes_rx++;
            processed_data++;
            if( escape_sequence < strlen(escape_seq_sourceip) && 
                ( escape_sequence > 0 ||
                 (current_timeval.tv_sec - last_data_timeval.tv_sec) * 1000 + (current_timeval.tv_usec - last_data_timeval.tv_usec) / 1000 > escape_pre_time 
                )
              )
            {   // check for escape character
                for( i=0; i<n && escape_sequence < strlen(escape_seq_sourceip); i++ )
                {
                    if( rxcharbuf[i] != escape_seq_sourceip[escape_sequence] )
                    {
                        escape_sequence = 0;
                        break;
                    }
                    
                    escape_sequence++;
                    flog( LOG_DEBUG, "escape sequence = %d", escape_sequence );
                }

                if( i<n )   // if there are more bytes in rx buffer, there was no delay after escape sequence
                    escape_sequence = 0;
            }                
            last_data_timeval.tv_sec = current_timeval.tv_sec;
            last_data_timeval.tv_usec = current_timeval.tv_usec;
        }
        else if( n == 0 )
            break;  // disconnected
        else if( escape_sequence == strlen(escape_seq_sourceip) && 
           (current_timeval.tv_sec - last_data_timeval.tv_sec) * 1000 + (current_timeval.tv_usec - last_data_timeval.tv_usec) / 1000 > escape_post_time )
        {
            escape_sequence++;  // delay after escape sequence was met, we are now in command-mode
            flog( LOG_INFO, "escape sequence for source IP received from destaddr" );
            // send IP address of source to dest
            snprintf( txcharbuf, sizeof(txcharbuf), "{%s}\r\n", inet_ntoa(srcaddress.sin_addr) );
            AddDataToCBuf( &srcrxbuf, (uint8_t *)txcharbuf, strlen(txcharbuf) );
            escape_sequence = 0;    // exit command-mode (escape sequence processing finished)
        }


        // check for data to send to source
        if( (n = CheckCBuf( &srcrxbuf )) )
        {
            if( n > tx_pkt_size )
                n = tx_pkt_size;
            n = GetDataFromCBuf( &srcrxbuf, (uint8_t *)txcharbuf, n, 0 );
            if( write( destfd, txcharbuf, n ) < 0 )
            {
                if( errno == EAGAIN || errno == EWOULDBLOCK )
                {   // stuff the data back in srcrxbuf
                    if( StuffDataInCBuf( &srcrxbuf, (uint8_t *)txcharbuf, n ) < 0 )
                    {
                        flog( LOG_DEBUG, "lost data in srctrxbuf" );
                    }
                }
                else
                    break;  // disconnected
            }
            processed_data++;
        }
        if( (n = CheckCBuf( &destrxbuf )) )
        {
            if( n > tx_pkt_size )
                n = tx_pkt_size;
            n = GetDataFromCBuf( &destrxbuf, (uint8_t *)txcharbuf, n, 0 );
            if( write( srcfd, txcharbuf, n ) < 0 )
            {
                if( errno == EAGAIN || errno == EWOULDBLOCK )
                {   // stuff the data back in destrxbuf
                    if( StuffDataInCBuf( &destrxbuf, (uint8_t *)txcharbuf, n ) < 0 )
                    {
                        flog( LOG_DEBUG, "lost data in destrxbuf" );
                    }
                }
                else
                    break;  // disconnected
            }
            processed_data++;
        }

        if( (no_answer_time > 0) && (serve_client_args->bytes_rx == 0) && (time(NULL) - connect_start_time > no_answer_time) )
            break;  // disconnect from this destaddr and attempt next destaddr    

        if( !processed_data )
        {
            // maybe should use poll() instead of nonblocking and a sleep?
            usleep(50);
        }
    }

    
    FreeCBuf(&srcrxbuf);
    FreeCBuf(&destrxbuf);
}


void *serve_client(void *_args)
{
    struct _serve_client_args *args = (struct _serve_client_args *)_args;
    char *addr_text = NULL;
    int i;
    int destfd = 0;
    struct sockaddr_in serv_addr; 
    char log_text[1024];
    int destaddr_ofs = 0;
    FILE *failmsg_file;
    int readbyte;
    int was_connected = 0;
    time_t connection_start_time;
    int ban_time_remaining;
    

    if( (ban_time_remaining = check_banned( args->address.sin_addr )) )
    {
        flog( LOG_INFO, "banned IP attempted to connect: %s (%d minutes left in ban)", inet_ntoa(args->address.sin_addr), ban_time_remaining+1 );
        print_banned_msg( args->srcfd, args->address, ban_time_remaining );
        close(args->srcfd);
        free( args );
        return NULL;
    }

    addr_text = inet_ntoa(args->address.sin_addr);
    if( addr_text )
        flog( LOG_INFO, "connection from %s", addr_text );
    else
        flog( LOG_ERROR, "inet_ntoa() failed to return addr_text" );


    // calculate destaddr_ofs, this is where in the list of destaddr[] to start attempting connections
    destaddr_ofs = listenaddr[args->listen_idx].last_destaddr % listenaddr[args->listen_idx].num_destaddr;
    for( i=0 ; i<listenaddr[args->listen_idx].num_destaddr; i++ )
    {
        if((destfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        {
            flog( LOG_ERROR, "serve_client() Could not create socket" );
            continue;
        }

        memset(&serv_addr, 0, sizeof(serv_addr)); 
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_addr = listenaddr[args->listen_idx].destaddr[(i + destaddr_ofs) % listenaddr[args->listen_idx].num_destaddr].addr;
        serv_addr.sin_port = htons(listenaddr[args->listen_idx].destaddr[(i + destaddr_ofs) % listenaddr[args->listen_idx].num_destaddr].port);

        snprintf( log_text, sizeof(log_text), "%s", inet_ntoa(args->address.sin_addr) );
        addr_text = inet_ntoa(serv_addr.sin_addr);
        flog( LOG_DEBUG, "attempting to connect %s to %s:%d", log_text, addr_text, ntohs(serv_addr.sin_port) );

        if( connect(destfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
        {
            flog( LOG_DEBUG, "failed to connect to %s:%d", addr_text, ntohs(serv_addr.sin_port) );
            continue;   // try next entry in destaddr[]
        }

        // update the last destaddr[] that was connected to, so next attempt starts at +1 to cycle through them all
        listenaddr[args->listen_idx].last_destaddr = (i + destaddr_ofs + 1) % listenaddr[args->listen_idx].num_destaddr;

        // set srcfd to non-blocking
        if( fcntl(destfd, F_SETFL, fcntl(destfd, F_GETFL, 0) | O_NONBLOCK) == -1 )
        {
            flog( LOG_ERROR, "error setting destfd to non-blocking" );
            // handle the error.  By the way, I've never seen fcntl fail in this way
        }

        if( addr_text )
        {
            snprintf( log_text, sizeof(log_text), "%s", inet_ntoa(args->address.sin_addr) );
            flog( LOG_INFO, "connected %s to %s:%d", log_text, inet_ntoa(serv_addr.sin_addr), ntohs(serv_addr.sin_port) );
        }

        connection_start_time = time(NULL);
        passthru_connection( args->srcfd, args->address, destfd, serv_addr.sin_addr, ntohs(serv_addr.sin_port), args );

        snprintf( log_text, sizeof(log_text), "%s:%d", inet_ntoa(serv_addr.sin_addr), ntohs(serv_addr.sin_port) );
        flog( LOG_INFO, "disconnected %s from %s (%d seconds)", inet_ntoa(args->address.sin_addr), log_text, time(NULL)-connection_start_time );

        if( args->bytes_rx < 1 )
        {   // if there was no traffic then consider the connection unsuccessful and continue to attempt connection to next destaddr[]
            close(destfd);
            continue;
        }

        was_connected = 1;

        close(destfd);
        
        break;
    }
    // no connection possible

    if( (!was_connected) && strlen(failmsg_filename) && (failmsg_file = fopen( failmsg_filename, "rt" )) )
    {   // print failmsg to client to let them know we were unable to complete their connection
        while( !feof(failmsg_file) && !ferror(failmsg_file) )
        {
            if( readbyte < 0 )
            {
                readbyte = fgetc(failmsg_file);
                if( feof(failmsg_file) || ferror(failmsg_file) )
                    break;
            }
            
            if( write( args->srcfd, &readbyte, 1 ) < 0 )
            {
                if( errno == EAGAIN || errno == EWOULDBLOCK )
                    continue;
                else
                    break;  // disconnected
            }

            readbyte = -1;  // set readbyte to -1 so next byte will be read from file
        }
        
        fclose(failmsg_file);
        sleep(2);        // sleep so failmsg is sent before socket is closed
    }


    close(args->srcfd);
    
    free(args);


    return NULL;
}


void *listen_port(void *_listen_idx)
{
    int *listen_idx = (int *)_listen_idx;
    int listenfd = 0;
    int connfd = 0;
    struct sockaddr_in serv_addr; 
    struct sockaddr_in address;
    socklen_t address_len = sizeof(address);
    int bind_attempts;
    int max_bind_attempts = 60;
    struct _serve_client_args *serve_client_args;
	pthread_t thread_id;

    
    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    if( listenfd < 0 )
    {
        // error
        goto cleanup;
    }
    memset(&serv_addr, 0, sizeof(serv_addr));

    serv_addr.sin_family = AF_INET;

    if( listenaddr[*listen_idx].addr.s_addr == 0 )
        serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    else
        serv_addr.sin_addr = listenaddr[*listen_idx].addr;
    
    serv_addr.sin_port = htons(listenaddr[*listen_idx].port); 


    bind_attempts = 0;
    while( bind(listenfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) != 0 )
    {
        bind_attempts++;
        // error binding to socket, error value in errno
        if( bind_attempts == 1 )
        {
            flog( LOG_ERROR, "unable to bind socket. errno=%d. retrying up to %d seconds...", errno, max_bind_attempts );
//            printf( "unable to bind socket. errno=%d. retrying up to %d seconds...\n", errno, max_bind_attempts );
        }
        else
            flog( LOG_DEBUG, "unable to bind socket. errno=%d. retrying up to %d seconds...", errno, max_bind_attempts-bind_attempts+1 );

        if( bind_attempts > max_bind_attempts )
        {
            flog( LOG_ERROR, "unable to bind socket. errno=%d. aborting.", errno );
            goto cleanup;
        }
        
        sleep(1);
    }


    if( listen(listenfd, 10) != 0 )
    {
        // error value in errno
        flog( LOG_ERROR, "unable to listen to socket. errno=%d", errno );
        goto cleanup;
    }


    flog( LOG_INFO, "ringdown listenaddr[%d] on %s:%d", *listen_idx, listenaddr[*listen_idx].addr.s_addr ? inet_ntoa(listenaddr[*listen_idx].addr) : "*", listenaddr[*listen_idx].port );


    // set listenfd to non-blocking
    if( fcntl(listenfd, F_SETFL, fcntl(listenfd, F_GETFL, 0) | O_NONBLOCK) == -1 )
        flog( LOG_ERROR, "error setting listen socket to non-blocking" );


    while(1)
    {
        connfd = accept(listenfd, (struct sockaddr *)&address, &address_len); 
        if( connfd < 0 )
        {
            // error value in errno
            usleep(10000);
            continue;
        }
        
        // set srcfd to non-blocking
        if( fcntl(connfd, F_SETFL, fcntl(connfd, F_GETFL, 0) | O_NONBLOCK) == -1 )
            flog( LOG_ERROR, "error setting srcfd to non-blocking" );

        // it will be the responsibility of serve_client() to free serve_client_args
        serve_client_args = (struct _serve_client_args *)calloc(1, sizeof(struct _serve_client_args));
        if( !serve_client_args )
        {
            flog( LOG_ERROR, "error allocating serve_client_args!" );
            continue;
        }

        serve_client_args->srcfd = connfd;
        serve_client_args->address = address;
        serve_client_args->listen_idx = *listen_idx;
        if( pthread_create( &thread_id, NULL , serve_client, (void*) serve_client_args) < 0)
        {
            flog( LOG_ERROR, "error creating thread serve_client" );
            continue;
        }
    }


cleanup:
     
     
    return NULL;
}


volatile int sigint_received = 0;

void INThandler(int sig)
{
    signal( sig, SIG_IGN );
    
    sigint_received = 1;    
}



int main(int argc, char *argv[])
{
    int opt;                            // for command-line parsing
    char *optarg;
    int i;
	pthread_t *listen_thread_ids;
    int *listen_idxs=NULL;
    struct stat fstat_buf;


    // parse command-line arguments (argv)                                                
    for( i=1; i<argc; i++ )
	{
	    opt = -1;
	    if( argv[i][0] == '-' )
            opt = argv[i][1];
            
        optarg = NULL;
        switch( opt )
        {
            case 'c':       // params that have arguments
            case 'l':
            case 'v':
                i++;
                if( i<argc )
                    optarg = argv[i];
                else
                {
                    printf( "command-line error - aborting.\n" );
                    return 1;
                }
                break;
        }

		switch (opt)
		{
		    case 'h':
		    default:
                printf( "command-line options:\n"
                        "-h\t\t\tdisplay this help screen\n"
                        "-c <conf_filename>\tconfiguration file\n"
                        "-l <log_filename>\tlog file\n"
                        "-v <n>\t\t\tset log verbosity (5=DEBUG,4=INFO,3=WARN,2=ERROR,1=FATAL)\n"
                        "\n" );
		        return 1;

            case 'c':
                strncpy( conf_filename, optarg, sizeof(conf_filename) );
                conf_filename[sizeof(conf_filename)-1] = '\0';
                break;
    
            case 'l':
                strncpy( log_filename, optarg, sizeof(log_filename) );
                log_filename[sizeof(log_filename)-1] = '\0';
                break;
    
            case 'v':
                global_log_level = strtoul(optarg, NULL, 0);
                break;
        }  
    }


    open_log( log_filename );

    flog(LOG_INFO, "%s %s starting.", SOFTWARE_NAME, SOFTWARE_VERSION);

    read_conf_file(conf_filename);
    

    memset( &fstat_buf, 0, sizeof(struct stat) );
    stat( ban_list_filename, &fstat_buf );
    ban_list_mtime = fstat_buf.st_mtime;        // save last modification time of ban_list

    restore_ban_list(ban_list_filename);

    ban_list_mutex = (pthread_mutex_t *)calloc(1,sizeof(pthread_mutex_t));
    if( !ban_list_mutex )
    {
        flog( LOG_ERROR, "unable to allocate memory for ban_list_mutex!\n" );
        close_log();
        return -1;
    }
    pthread_mutex_init(ban_list_mutex, NULL);

    if( num_listenaddr > 0 )
    {
        listen_idxs = (int *)calloc(num_listenaddr, sizeof(int));
        if( !listen_idxs )
            flog(LOG_ERROR, "calloc error - %d bytes", num_listenaddr * sizeof(int));

        listen_thread_ids = (pthread_t *)calloc(num_listenaddr, sizeof(pthread_t));
        if( !listen_thread_ids )
            flog(LOG_ERROR, "calloc error - %d bytes", num_listenaddr * sizeof(pthread_t));
    }

    for( i=0; listen_idxs && listen_thread_ids && i<num_listenaddr; i++ )
    {   // spawn a thread for each listenaddr[]
        listen_idxs[i] = i;
        if( pthread_create( &listen_thread_ids[i], NULL, listen_port, (void*) &listen_idxs[i]) < 0)
        {
            perror("could not create thread");
            return 1;
        }
    }

    // listen_thread_ids[0..num_listenaddr] contain id for each listen_port thread running
    signal( SIGINT, INThandler );
    while(1)
    {
        if( sigint_received )
            break;


        memset( &fstat_buf, 0, sizeof(struct stat) );
        stat( ban_list_filename, &fstat_buf );

        if( fstat_buf.st_mtime != ban_list_mtime )
        {
            memset( &fstat_buf, 0, sizeof(struct stat) );
            stat( ban_list_filename, &fstat_buf );
            ban_list_mtime = fstat_buf.st_mtime;        // save last modification time of ban_list

            flog( LOG_INFO, "reloading ban_list '%s'", ban_list_filename );

            pthread_mutex_lock(ban_list_mutex);
            num_ban_list = 0;
            free(ban_list);
            ban_list = NULL;
            restore_ban_list(ban_list_filename);
            pthread_mutex_unlock(ban_list_mutex);           
        }


        sleep(1);
    }
    
    flog(LOG_DEBUG, "terminating threads");

//NOTE - we don't have a list of threads of currently active connections

    // terminate threads    
    for( i=0; listen_idxs && listen_thread_ids && i<num_listenaddr; i++ )
        pthread_cancel( listen_thread_ids[i] );

    // wait for threads to terminate
    for( i=0; listen_idxs && listen_thread_ids && i<num_listenaddr; i++ )
        pthread_join( listen_thread_ids[i], NULL );

    save_ban_list(ban_list_filename);
    
    flog(LOG_INFO, "%s exiting.", SOFTWARE_NAME);

    close_log();
    
    if( listen_idxs )
        free(listen_idxs);


    return 0;
}
