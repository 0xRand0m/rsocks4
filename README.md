# rsocks4
Reverse ssh SOCKS4 proxy

Does the inverse operation to `ssh -D` - opens an SSH session on a remote server and opens port there that acts as a SOCKS4a proxy that routes connections through the client.

Neither feature complete nor well tested ;)

```
usage: rsocks4.py [-h] [-i KEY_FILE] [-p PORT] [--pw PW] destination remote_port

positional arguments:
  destination  [user@]host - destination to connect to
  remote_port  Port to listen on at the remote host

optional arguments:
  -h, --help   show this help message and exit
  -i KEY_FILE  private key to use
  -p PORT      port to connect to
  --pw PW      password/private key passphrase
```
