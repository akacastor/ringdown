#ifndef _RINGDOWN_H
#define _RINGDOWN_H

#include <stdint.h>


extern int default_connecttime;


extern struct _listenaddr *listenaddr;
extern int num_listenaddr;

extern char failmsg_filename[1024];


struct _listenaddr
{
    struct in_addr addr;
    uint16_t port;

    struct _destaddr *destaddr;
    int num_destaddr;
    int last_destaddr;
    
    int connecttime;
    
    char *failmsg;
};


struct _destaddr
{
    struct in_addr addr;
    uint16_t port;
};


#endif  // _RINGDOWN_H
