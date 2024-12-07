#ifndef _RINGDOWN_H
#define _RINGDOWN_H

#include <stdint.h>


#define SOFTWARE_NAME       "ringdown"
#define SOFTWARE_VERSION    "0.53"


extern int default_connecttime;


extern struct _listenaddr *listenaddr;
extern int num_listenaddr;

extern char failmsg_filename[1024];

extern int no_answer_time;  // time (in seconds) after which we will disconnect from destaddr if they haven't sent any data yet

extern unsigned int escape_pre_time;    // time (in ms) that must be idle before +++ escape sequence
extern unsigned int escape_post_time;    // time (in ms) that must be idle after +++ escape sequence
extern char escape_seq_sourceip[1024];

extern char notify_connection_cmd[1024];    // command to execute via system() when a connection is established

extern struct _ip_ban *ban_list;
extern int num_ban_list;

extern struct _ip_ban *ban_list;
extern int num_ban_list;
extern int ban_time;                       // ban time in minutes (for first attempt, will be multiplied by ban_multiplier on subsequent bans)
extern int ban_multiplier;                 // factor by which to increase ban time with each attempt
extern int max_ban_time;                   // maximum length of a ban in minutes
extern char bannedmsg_filename[1024];
extern int bot_detect_time;                // how long to watch for suspicious login attempts, in seconds
extern char **bad_words;
extern int num_bad_words;
extern int bot_sleep_time;                 // seconds to sleep() for before disconnecting bot (slow them down where we can)


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


struct _ip_ban
{
    struct in_addr addr;    
    time_t expire_time;     // timestamp of when the ban expires
    unsigned long count;              // # of times this IP has been banned (length of ban may increase with count)
    unsigned long connect_attempts;   // # of times this IP has attempted to connect while banned
};



#endif  // _RINGDOWN_H
