# portforwardingsshd
Simple SSH daemon for port forwarding only written in golang

# To connect to this server, use:
ssh -N -oServerAliveInterval=30 -i <server_provided_priv_key> -R <reverse_connect_port>:<remote_host>:<remote_port> -p <port> <host>

## Exemple:
ssh -N -i ~/.ssh/provided_key.pem -R 4444:localhost:22 -p 22 my.reverse.host.net

### To Use:
ssh -N -i ~/.ssh/provided_key.pem -L 5556:localhost:4444 -p 22 localhost

#### then:
nc localhost 5556

### OR:
ssh -oProxyCommand='ssh -i ~/.ssh/provided_key.pem -p 4444 localhost nc %h %p' -p 22 localhost
