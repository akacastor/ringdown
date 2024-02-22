# ringdown
Telnet Ringdown server to accept connections and proxy them to a list of addresses/ports.



Telnet Ringdown Server
----------------------


main()

read config file

for each listenaddr[] create a thread: listen_port()

wait




listen_port()

bind to address:port and listen for a connection

connection received:

check IP address against ban list - display banned msg & disconnect if in list and current

create a thread: serve_client()

wait for next connection



serve_client()

go through destaddr[] list and attempt to connect

when connection is successful, call passthru_connection() to link client and dest



passthru_connection()

receive data from client and send to dest

receive data from dest and send to client

bot detection happens here also



