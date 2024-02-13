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
        else
        {
            flog( LOG_ERROR, "conf line %d: unrecognized token '%s'", line_num, tok );
            continue;
        }
    }


    fclose( conf_file );

    
    return 0;
}
