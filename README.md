# portforwardingsshd
Simple SSH daemon for port forwarding only written in golang

To connect to this server, use:
ssh -N -i <server_provided_priv_key> -R <reverse_connect_port>:<remote_host>:<remote_port> -p <port> <host>

Exemple:
ssh -N -i ~/.ssh/provided_key.pem -R 2222:localhost:22 -p 22 my.reverse.host.net
