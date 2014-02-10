#!/usr/bin/env python
"""SNI SSL Termination router.
   * Retrieves keys/certs from remote keystores and caches them locally.
   * Terminates ssl, proxies to http/https backends
"""
from gevent import monkey
monkey.patch_all()
import sys
import signal
import struct
import ssl
import StringIO
import errno

import gevent
import tlslite.constants
import umysql
from gevent.pywsgi import WSGIServer


class Snipe(WSGIServer):

    def handle(self, source, address):
        log('%s:%s accepted', *address[:2])
        WSGIServer.handle(self, source, address)

    def wrap_socket_and_handle(self, client_socket, address):
        sni_host = self.recv_clienthello(client_socket)
        print sni_host
        cnn = umysql.Connection()
        cnn.connect ('localhost', 3306, "root", "", "publisherregistry")
        rs = cnn.query("select 1")
        print self.ssl_args
        if sni_host is not None:
            self.ssl_args['keyfile'] = '/Volumes/tmp/%s.key' % sni_host
            self.ssl_args['certfile'] = '/Volumes/tmp/%s.crt' % sni_host
        WSGIServer.wrap_socket_and_handle(self, client_socket, address)

    def init_socket(self):
        WSGIServer.init_socket(self)

    def recv_clienthello(self, sock):

        while True:
            try:
                peek_data = sock._sock.recv(1024, gevent.socket.MSG_PEEK)
                break
            except gevent.socket.error, e:
                if e.errno == errno.EAGAIN:
                    gevent.sleep(0)
                else:
                    raise e

        peek_bytes = StringIO.StringIO()
        peek_bytes.write(peek_data)
        peek_bytes.seek(0)

        header_bytes = []
        header_bytes.append(peek_bytes.read(1))
        header_bytes[0] = struct.unpack('!B', header_bytes[0])[0]

        if header_bytes[0] & 0x80:
            # Version 2.0 Client "Record Layer"
            header_bytes.append(peek_bytes.read(1))
            header_bytes[1] = struct.unpack('!B', header_bytes[1])[0]
            msg_length = (header_bytes[0] & 0x7f) << 8 | header_bytes[1]
            msg_version_major = 2
            msg_version_minor = 0
            msg_type = tlslite.constants.ContentType.handshake
            record = peek_bytes.read(msg_length)
        else:
            header = peek_bytes.read(4)
            msg_type = header_bytes[0]
            msg_version_major, msg_version_minor, msg_length = struct.unpack('!BBH', header)
            record = peek_bytes.read(msg_length)

        try:
            SNI_LEN_POS = 99
            sni_value_len = struct.unpack('!B', record[SNI_LEN_POS])[0]
            sni_value = record[SNI_LEN_POS + 1 :SNI_LEN_POS + sni_value_len + 1]
            #return msg_type, msg_version_major, msg_version_minor, record
            return sni_value
        except:
            pass

    def close(self):
        if self.closed:
            sys.exit('Multiple exit signals received - aborting.')
        else:
            log('Closing listener socket')
            WSGIServer.close(self)


def forward(source, dest):
    source_address = '%s:%s' % source.getpeername()[:2]
    dest_address = '%s:%s' % dest.getpeername()[:2]
    try:
        while True:
            data = source.recv(1024)
            log('%s->%s: %r', source_address, dest_address, data)
            if not data:
                break
            dest.sendall(data)
    finally:
        source.close()
        dest.close()


def parse_address(address):
    try:
        hostname, port = address.rsplit(':', 1)
        port = int(port)
    except ValueError:
        sys.exit('Expected HOST:PORT: %r' % address)
    return gethostbyname(hostname), port


def application(environ, start_response):
    status = '200 OK'

    body = 'FOO BAR'
    headers = [
        ('Content-Type', 'text/html')
    ]

    start_response(status, headers)
    return [body]



def main():
    args = sys.argv[1:]
    if len(args) != 1:
        sys.exit('Usage: %s source-address' % __file__)
    source = args[0]
    server = Snipe(source,
                application=application,
                keyfile='/Volumes/tmp/server.key',
                certfile='/Volumes/tmp/server.crt',
                #do_handshake_on_connect=False,
                #server_side=True,
            )
    log('Starting snipe %s:%s', *(server.address[:2]))
    gevent.signal(signal.SIGTERM, server.close)
    gevent.signal(signal.SIGINT, server.close)
    #server.start()
    #gevent.wait()
    server.serve_forever()

def log(message, *args):
    message = message % args
    sys.stderr.write(message + '\n')


if __name__ == '__main__':
    main()
