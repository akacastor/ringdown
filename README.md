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


## Configuring the Telnet Ringdown server

Edit configuration options in ringdown.conf


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


## Software architecture

### main()

* read config file
* for each listenaddr[] create a thread: listen_port()
* wait

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


## Bot detection

* Pressing Escape disables bot detection - when client presses escape to enter BBS this is considered a sign that they are not a bot.
* During first 'bot_detect_time' seconds of connection, any data sent from the client is monitored for keywords indicating brute force attempt.
* Typical bot behaviour: send "root\r" followed by a default password attempt.
