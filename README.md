# ringdown
Telnet Ringdown server to accept connections and proxy them to a list of addresses/ports.


## About the Telnet Ringdown server

_Why use the Telnet Ringdown server?_

* Accept multiple connections to a port and connect them to a list of addresses/ports.
* Connections can be forwarded to another IP for use as a telnet reverse proxy.
* Bot detection: Reduce the number of connections from IP scanners attempting default credential logins.


## Building the Telnet Ringdown server

Build in Linux by typing:

make


## Operating the Telnet Ringdown server

Command line options:
```
-h                  display help screen
-c <conf_filename>  specify configuration filename
-l <log_filename>   log file
-v <n>              set log verbosity (1=FATAL,2=ERROR,3=WARN,4=INFO,5=DEBUG)
```
When an IP is banned, it will be added to ringdown.ban.

If ringdown.ban is edited, it will be reloaded by the Telnet Ringdown server. This can be used to manually add/remove IPs on the ban list.

If a client connects and its IP is found in the ban list, the client will be shown the file banned.txt and disconnected.

If a client connects and ringdown is unable to open a connection with a server, the client will be shown the file failed_to_connect.txt and disconnected.


## Caller ID

The server (destaddr who accepted our connection) may transmit a delay of 1 second, followed by the escape sequence `}}}SOURCEIP?`, followed by a delay of 1 second, to retrieve a string like `{1.2.3.4}` with the client's IP address.  The use of }}} in the escape code is chosen to not conflict with other softmodem implementations that may be using +++ already.


## Bot detection

When client is first connected to server, the Telnet Ringdown server will monitor data sent by the client to the server. If an attempt at a default credentials login is detected, the client's IP will be temporarily banned from connecting.

The bot detection is intended to have limited risk of false positives - we don't want to accidentally ban non-malicious clients.  Two features to support this are:
* If the client sends an Esc keypress (0x1B), bot detection is disabled.
* After 'bot_detect_time' seconds, the bot detection is disabled.

The client pressing escape to enter the BBS is considered a sign that they are not a bot.  If an escape keypress is not received, 'bot_detect_time' will expire by the time the front-end mailer times out and passes control to the BBS for login, reducing chance of BBS login triggering a false positive.

Set log level to DEBUG (`-v 5`) to log suspicious strings detect during client connections.
* `login attempt from 123.175.88.231? 'hikvision'`
* add `bad_word hikvision` to ringdown.conf to ban bots using this login attempt.


## Configuring the Telnet Ringdown server

Edit configuration options in ringdown.conf

```
; telnet ringdown configuration
;
; you must have at least one listenaddr
; after listenaddr, specify a list of destaddr (one or more)

; listen on address * for all interfaces
listenaddr  *:23

destaddr 127.0.0.1:2301
destaddr 127.0.0.1:2302
destaddr 127.0.0.1:2303


;listenaddr  *:2320
;destaddr 192.168.1.100:2311


; failmsg specifies file to send client when no server is available
; comment out failmsg to disable
failmsg failed_to_connect.txt


; if there is no data from destaddr after 5 seconds of connection, move on to next destaddr
; this is useful in case a node is hung but the telnet connection is accepted - after 5 seconds we move on
no_answer_time 5


; time (milliseconds) that must be idle before receiving escape sequence from destaddr
escape_pre_time 800

; time (milliseconds) that must be idle after receiving escape sequence from destaddr
escape_post_time 800

; escape sequence that will trigger {SOURCEIP} being sent to destaddr
escape_seq_sourceip }}}SOURCEIP?


; ban time in minutes (for first attempt, will be multiplied by ban_multiplier on subsequent bans)
ban_time 5

; factor by which to increase ban time with each attempt
ban_multiplier 5

; maximum length of a ban in minutes (10080 = 1 week)
max_ban_time 10080

bannedmsg banned.txt

; how long to watch for suspicious login attempts, in seconds
bot_detect_time 20

; how long to leave connection hanging after banning a bot
bot_sleep_time 30

; list of words (case-insensitive) considered bot login attempts (ie: root, admin)
bad_word 123
bad_word 1234
bad_word Administrator
bad_word D-Link
bad_word Epuser
bad_word MAIL
bad_word MD110
bad_word NAU
bad_word ONTUSER
bad_word ______
bad_word aaa
bad_word admin
bad_word admintelecom
bad_word adminttd
bad_word adtecftp
bad_word apc
bad_word beardropper sh shell
bad_word bin
bad_word browse
bad_word cht
bad_word daemon
bad_word default
bad_word fliruser
bad_word ftp
bad_word guest
bad_word guest1
bad_word home
bad_word icinga
bad_word init
bad_word lnadmin
bad_word manager
bad_word mtch
bad_word nil
bad_word nobody
bad_word ont
bad_word pi
bad_word remotessh
bad_word root
bad_word scmadmin
bad_word sh
bad_word steam
bad_word stratacom
bad_word super
bad_word superadmin
bad_word support
bad_word supportadmin
bad_word telecomadmin
bad_word telnet
bad_word telnetadmin
bad_word test
bad_word ubnt
bad_word user
bad_word useradmin
bad_word usuario
bad_word vadmin
bad_word vstarcam2015
bad_word wradmin
bad_word zyfwp
bad_word hikvision
```


## Software architecture

### main()

* read config file
* for each listenaddr[] create a thread: listen_port()
* watch for updates to ringdown.ban and reload

### listen_port() (thread)

* bind to address:port and listen for a connection
* connection received:
* check IP address against ban list - display banned msg & disconnect if in list and current
* create a thread: serve_client()
* wait for next connection

### serve_client() (thread)

* go through destaddr[] list and attempt to connect
* when connection is successful, call passthru_connection() to link client and dest

### passthru_connection()

* receive data from client and send to dest
* receive data from dest and send to client
* bot detection happens here also
