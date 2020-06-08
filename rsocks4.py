#!/usr/bin/env python3

import sys
import struct
import socket
import select
import argparse
import threading
import getpass
import paramiko
import logging

logging.basicConfig(level=logging.INFO)

logger = logging.getLogger(__name__)

SOCKS_VERSION = 4

def socks4handler(channel):
    header = channel.recv(1024)
    logger.debug(f'received header: {header}')
    if len(header) < 9:
        logger.error(f'malformed initial packet from - dropping channel')
        logger.debug(f'packet data: {header}')
        channel.close()
        return
    version, cmd, dst_port, ip = struct.unpack('!BBHI', header[:8])
    try:
        client_id = header[8:].decode('ascii')
    except Exception as e:
        logger.warning('unable to parse client id as ascii')
        client_id = 'unknown'

    if version != 4:
        logger.error(f'Version negotiation failed, client version: {version}. Dropping channel.')
        channel.send(b'\x00\x5b\x00\x00\x00\x00\x00\x00\x00')
        channel.close()
        return

    # in this case the server is in the domain part (SOCKS4a)
    if ip <= 0xFF:
        pp = header[8:].split(b'\x00')
        if len(pp) < 2:
            logger.error(f"invalid request can't determin host from f{header[4:]} -  dropping channel")
            channel.send(b'\x00\x5b\x00\x00\x00\x00\x00\x00\x00')
            channel.close()
            return
        dst_addr = pp[1].decode('ascii')
    else:
        try:
            dst_addr = socket.inet_ntoa(header[4:8])
        except Exception as e:
            logger.error('Unable to parse destination ip - dropping channel', exc_info=True)
            channel.send(b'\x00\x5b\x00\x00\x00\x00\x00\x00\x00')
            channel.close()
            return


    logger.debug(f'Attempting connection to {dst_addr}:{dst_port}')

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        sock.connect((dst_addr, dst_port))
    except Exception as e:
        logger.error(f'Connection to {dst_addr}:{dst_port} failed - dropping channel')
        channel.send(b'\x00\x5b\x00\x00\x00\x00\x00\x00\x00')
        channel.close()
        return

    channel.send(b'\x00\x5a\x00\x00\x00\x00\x00\x00')

    logger.debug('Connection established')

    while True:
        r, w, e = select.select([channel, sock], [], [])

        if channel in r:
            data = channel.recv(4096)
            if sock.send(data) <= 0:
                break

        if sock in r:
            data = sock.recv(4096)
            if channel.send(data) <= 0:
                break

    channel.close()
    sock.close()

def main():
    argp = argparse.ArgumentParser()
    argp.add_argument('-i', action='store', dest='key_file', default=None, help='private key to use')
    argp.add_argument('-p', action='store', dest='port', type=int, default=22, help='port to connect to')
    argp.add_argument('--pw', action='store', dest='pw', default=None, help='password/private key passphrase')
    argp.add_argument('destination', action='store', help='[user@]host - destination to connect to')
    argp.add_argument('remote_port', action='store', type=int, help='Port to listen on at the remote host')

    options = argp.parse_args(sys.argv[1:])

    client = paramiko.client.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.WarningPolicy())

    destination = options.destination.split('@')
    host = destination[0]
    user = None
    if len(destination) >= 2:
        host = destination[1]
        user = destination[0]

    logger.info(f'Connecting to {host}:{options.port}')

    kwargs = {
            'port': options.port,
            'username': user,
            }

    pkey = None
    pw = options.pw
    if options.key_file:
        passphrase = options.pw
        while True:
            try:
                pk = paramiko.rsakey.from_private_key_file(options.key_file)
                kwargs['pkey'] = pk
                break
            except paramiko.PasswordRequiredException:
                passphrase = getpass.getpass('private key passphrase: ')
            except paramiko.SSHException:
                logger.fatal('invalid private key')
                sys.exit(1)
    elif pw is None:
        pw = getpass.getpass('password: ')
        kwargs['password'] = pw
    else:
        kwargs['password'] = pw


    try:
        client.connect(
                host,
                **kwargs
                )
    except Exception as e:
        logger.critical('[!] Unable to connect', exc_info=True)
        sys.exit(1)

    transport = client.get_transport()

    transport.request_port_forward('127.0.0.1', options.remote_port)

    while True:
        chan = transport.accept(1000)
        if chan is None:
            continue
        thr = threading.Thread(target=socks4handler, args=(chan,))
        thr.setDaemon(True)
        thr.start()

if __name__ == '__main__':
    main()
