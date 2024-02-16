#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <arpa/inet.h>

#include "ringdown.h"
#include "log.h"


int read_conf_file(const char *filename)
{
    FILE *conf_file;
    const int linebuflen = 1024;    
    char linebuf[linebuflen];
    char *filename_sep = "\n";
    char *sep = " \t=:\n";
    char *tok = NULL;
    char *val = NULL;
    int line_num = 0;
    char *new_bad_word;

    
    if( !filename )
        return -1;
        
    conf_file = fopen( filename, "rt" );
    if( !conf_file )
        return -2;

    while( !feof(conf_file) && !ferror(conf_file) )
    {        
        if( !fgets( linebuf, sizeof(linebuf), conf_file ) )
            break;            
        line_num++;
        
        tok = strchr(linebuf, ';');
        if( tok )
            *tok = '\0';    // insert NULL where ; comment was found
        
        tok = strtok( linebuf, sep );
        if( !tok )
            continue;

        if( !strcasecmp( tok, "listenaddr" ) )
        {
            val = strtok( NULL, sep );            
            if( !val )
            {
                flog( LOG_ERROR, "conf line %d: listenaddr requires parameter (IP address or *)", line_num );
                continue;
            }

            num_listenaddr++;
            listenaddr = (struct _listenaddr *)realloc(listenaddr, sizeof(struct _listenaddr) * num_listenaddr);
            if( !listenaddr )
            {   // memory allocation error
                num_listenaddr = 0;
                fclose( conf_file );
                return -3;
            }
            
            // initialize new listenaddr[] to 0
            memset( &listenaddr[num_listenaddr-1], 0, sizeof(struct _listenaddr) );

            if( !strcasecmp( val, "*" ) )
            {
                listenaddr[num_listenaddr-1].addr.s_addr = 0;
            }
            else
            {
                listenaddr[num_listenaddr-1].addr.s_addr = inet_addr(val);
                if( listenaddr[num_listenaddr-1].addr.s_addr == (in_addr_t)(-1) )
                {
                    flog( LOG_ERROR, "conf line %d: invalid listenaddr parameter", line_num );
                    continue;
                }
            }            

            val = strtok( NULL, sep );
            if( !val )
            {
                listenaddr[num_listenaddr-1].port = 23;       // default = port 23 (telnet)
                continue;
            }
            
            listenaddr[num_listenaddr-1].port = strtoul(val, NULL, 0);
            if( listenaddr[num_listenaddr-1].port == 0 )
            {
                listenaddr[num_listenaddr-1].port = 23;
                flog( LOG_ERROR, "conf line %d: listenaddr IP:port parse error - using port %d", line_num, listenaddr[num_listenaddr-1].port );
            }
        }
        else if( !strcasecmp( tok, "destaddr" ) )
        {
            if( num_listenaddr < 1 )
            {
                flog( LOG_ERROR, "conf line %d: destaddr not valid before listenaddr", line_num );
                continue;
            }
            
            val = strtok( NULL, sep );
            if( !val )
            {
                flog( LOG_ERROR, "conf line %d: destaddr requires parameter (IP:port)", line_num );
                continue;
            }
            
            listenaddr[num_listenaddr-1].num_destaddr++;
            listenaddr[num_listenaddr-1].destaddr = (struct _destaddr *)realloc(listenaddr[num_listenaddr-1].destaddr, sizeof(struct _destaddr) * listenaddr[num_listenaddr-1].num_destaddr);
            if( !listenaddr[num_listenaddr-1].destaddr )
            {   // memory allocation error
                listenaddr[num_listenaddr-1].num_destaddr = 0;
                fclose( conf_file );
                return -4;
            }

            // initialize new destaddr[] to 0
            memset( &listenaddr[num_listenaddr-1].destaddr[listenaddr[num_listenaddr-1].num_destaddr-1], 0, sizeof(struct _destaddr) );
            
            listenaddr[num_listenaddr-1].destaddr[listenaddr[num_listenaddr-1].num_destaddr-1].addr.s_addr = inet_addr(val);
            
            val = strtok( NULL, sep );
            if( !val )
            {
                listenaddr[num_listenaddr-1].destaddr[listenaddr[num_listenaddr-1].num_destaddr-1].port = 23;       // default = port 23 (telnet)
                continue;
            }
            
            listenaddr[num_listenaddr-1].destaddr[listenaddr[num_listenaddr-1].num_destaddr-1].port = strtoul(val, NULL, 0);
            if( listenaddr[num_listenaddr-1].destaddr[listenaddr[num_listenaddr-1].num_destaddr-1].port == 0 )
            {
                listenaddr[num_listenaddr-1].destaddr[listenaddr[num_listenaddr-1].num_destaddr-1].port = 23;
                flog( LOG_ERROR, "conf line %d: destaddr IP:port parse error - using port %d", line_num, listenaddr[num_listenaddr-1].destaddr[listenaddr[num_listenaddr-1].num_destaddr-1].port );
            }
        }
        else if( !strcasecmp( tok, "failmsg" ) )
        {            
            val = strtok( NULL, filename_sep );
            if( !val )
            {
                flog( LOG_ERROR, "conf line %d: failmsg requires parameter (filename)", line_num );
                continue;
            }
            
            strncpy( failmsg_filename, val, sizeof(failmsg_filename) );
            failmsg_filename[sizeof(failmsg_filename)-1] = '\0';
            
            flog( LOG_DEBUG, "failmsg filename: '%s'", failmsg_filename );
        }
        else if( !strcasecmp( tok, "no_answer_time" ) )
        {            
            val = strtok( NULL, filename_sep );
            if( !val )
            {
                flog( LOG_ERROR, "conf line %d: no_answer_time requires parameter (time in seconds)", line_num );
                continue;
            }
            
            no_answer_time = strtoul( val, NULL, 0 );
            
            flog( LOG_DEBUG, "no_answer_time: %d", no_answer_time );
        }
        else if( !strcasecmp( tok, "escape_pre_time" ) )
        {            
            val = strtok( NULL, filename_sep );
            if( !val )
            {
                flog( LOG_ERROR, "conf line %d: escape_pre_time requires parameter (time in milliseconds)", line_num );
                continue;
            }
            
            escape_pre_time = strtoul( val, NULL, 0 );
            
            flog( LOG_DEBUG, "escape_pre_time: %d", escape_pre_time );
        }
        else if( !strcasecmp( tok, "escape_post_time" ) )
        {            
            val = strtok( NULL, filename_sep );
            if( !val )
            {
                flog( LOG_ERROR, "conf line %d: escape_post_time requires parameter (time in milliseconds)", line_num );
                continue;
            }
            
            escape_post_time = strtoul( val, NULL, 0 );
            
            flog( LOG_DEBUG, "escape_post_time: %d", escape_post_time );
        }
        else if( !strcasecmp( tok, "escape_seq_sourceip" ) )
        {            
            val = strtok( NULL, filename_sep );
            if( !val )
            {
                flog( LOG_ERROR, "conf line %d: escape_seq_sourceip requires parameter (escape string)", line_num );
                continue;
            }
            
            strncpy( escape_seq_sourceip, val, sizeof(escape_seq_sourceip) );
            escape_seq_sourceip[sizeof(escape_seq_sourceip)-1] = '\0';
            
            flog( LOG_DEBUG, "escape_seq_sourceip: '%s'", escape_seq_sourceip );
        }
        else if( !strcasecmp( tok, "bannedmsg" ) )
        {            
            val = strtok( NULL, filename_sep );
            if( !val )
            {
                flog( LOG_ERROR, "conf line %d: bannedmsg requires parameter (filename)", line_num );
                continue;
            }
            
            strncpy( bannedmsg_filename, val, sizeof(bannedmsg_filename) );
            bannedmsg_filename[sizeof(bannedmsg_filename)-1] = '\0';
            
            flog( LOG_DEBUG, "bannedmsg filename: '%s'", bannedmsg_filename );
        }
        else if( !strcasecmp( tok, "ban_time" ) )
        {            
            val = strtok( NULL, filename_sep );
            if( !val )
            {
                flog( LOG_ERROR, "conf line %d: ban_time requires parameter (time in minutes)", line_num );
                continue;
            }
            
            ban_time = strtoul( val, NULL, 0 );
            
            flog( LOG_DEBUG, "ban_time: %d", ban_time );
        }
        else if( !strcasecmp( tok, "ban_multiplier" ) )
        {            
            val = strtok( NULL, filename_sep );
            if( !val )
            {
                flog( LOG_ERROR, "conf line %d: ban_multiplier requires parameter (time in minutes)", line_num );
                continue;
            }
            
            ban_multiplier = strtoul( val, NULL, 0 );
            
            flog( LOG_DEBUG, "ban_multiplier: %d", ban_multiplier );
        }
        else if( !strcasecmp( tok, "max_ban_time" ) )
        {            
            val = strtok( NULL, filename_sep );
            if( !val )
            {
                flog( LOG_ERROR, "conf line %d: max_ban_time requires parameter (time in minutes)", line_num );
                continue;
            }
            
            max_ban_time = strtoul( val, NULL, 0 );
            
            flog( LOG_DEBUG, "max_ban_time: %d", max_ban_time );
        }
        else if( !strcasecmp( tok, "bot_detect_time" ) )
        {            
            val = strtok( NULL, filename_sep );
            if( !val )
            {
                flog( LOG_ERROR, "conf line %d: bot_detect_time requires parameter (time in minutes)", line_num );
                continue;
            }
            
            bot_detect_time = strtoul( val, NULL, 0 );
            
            flog( LOG_DEBUG, "bot_detect_time: %d", bot_detect_time );
        }
        else if( !strcasecmp( tok, "bad_word" ) )
        {            
            val = strtok( NULL, filename_sep );
            if( !val )
            {
                flog( LOG_ERROR, "conf line %d: bad_word requires parameter (word)", line_num );
                continue;
            }
            
            
            num_bad_words++;
            bad_words = (char **)realloc( bad_words, num_bad_words * sizeof(char *));
            
            new_bad_word = (char *)calloc( strlen(val), sizeof(char) );
            if( !new_bad_word )
            {
                flog( LOG_ERROR, "error allocating memory for new_bad_word!" );
                continue;
            }
            
            strcpy( new_bad_word, val );
            bad_words[num_bad_words-1] = new_bad_word;
            
            flog( LOG_DEBUG, "bad_word: '%s'", val );
        }
        else
        {
            flog( LOG_ERROR, "conf line %d: unrecognized token '%s'", line_num, tok );
            continue;
        }
    }


    fclose( conf_file );

    
    return 0;
}
