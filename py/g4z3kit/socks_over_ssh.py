# -*- coding:utf-8 -*-
'''
An updated version of https://github.com/x007007007/sshtunnel

Adapted to suite Python 3
'''

import socketserver
import struct
import socket
import select
import paramiko
import threading


class SocksException(Exception):
    '''
        Base Socks Exception
    '''
    pass


class SocksIdentifyException(SocksException):
    """
        Socks identify protocol deal fail
    """
    pass


class SocksIdentifyFailed(SocksIdentifyException):
    """
        Socks identify fail
    """
    pass


class SocksIdentifyDisabled(SocksIdentifyException):
    """
        No identify require
    """
    pass


class SocksNegotiateException(SocksException):
    """
        Negotiate Exception
    """
    pass


class SocksAddressTypeDisabled(SocksNegotiateException):
    """
        Address flag not support
    """
    pass


class SocksRemoteException(SocksException):
    """
        remote socks error
    """
    pass


class SocksClientException(SocksException):
    """
        client error
    """
    pass


class SocksRequestHandler(socketserver.StreamRequestHandler):
    """
        defined get_sockes5_* functions to get remote socket for
        socksv5.
        defined socksv5_identifier to deal socksv5 identifier
        handle to select socks v5 or socks v4, only socksv5
        support now.
        defined handle_socks5 to deal sockesv5 required
    """
    def log(self, level, msg):
        """
        function to log info
        """
        pass  # print level,msg

    def get_s5_conn_sp(self, dst, src, dst_type=b'\x01'):
        '''
            create remote connect and return socket of this connect
            dst is a tuple (addr,port) which is connect dst
            dst_type x01 is ipv4
                     x02 is host_name
                     x04 is ipv6
            return remote_socket
        '''
        if (hasattr(self, 'server') and
                hasattr(self.server, 'socks') and
                hasattr(self.server.socks, 'connect_handle') and
                callable(self.server.socks.connect_handle)):
            return self.server.socks.connect_handle(dst,
                                                    src,
                                                    dst_type)
        return None, None

    def get_s5_bind_sp(self, dst, src, dst_type=b'\x01'):
        """
            create remote bind socket like get_socksv5_connect_socket
        """
        _, port = dst
        if dst_type in [b'\x01', b'\x03']:
            remote = socket.socket(socket.AF_INET,
                                   socket.SOCK_STREAM)
            remote.settimeout(5)
            remote.bind(('127.0.0.1', port + 9000))
            remote.listen(0)
        elif dst_type == b'\x04':
            remote = socket.socket(socket.AF_INET6,
                                   socket.SOCK_STREAM)
            remote.bind(('::', port + 9000))
            remote.listen(0)
        return remote

    def get_socks5_udp_socket(self, dst, src, dst_type=b'\x01'):
        """
            create remote udp socket
        """
        pass

    def socks5_identifier(self, methods):
        """
            socks v5 identificate active
            switch a identify method and finish methods
            if identify fail will raise Exception
        """
        if b'\x00' in methods:
            self.request.send(b'\x05\x00')
            return True
        else:
            msg = 'Just support No authentication required'
            raise SocksIdentifyDisabled(msg)

    def handle(self):
        """
            required entry to judge protocol version,
            select deal method and call it
        """
        recv = self.request.recv(512)
        self.log('debug', 'recv msg:%r' % recv)
        if recv[0] == 4:
            self.handle_socks4(recv)
        elif recv[0] == 5:
            self.handle_socks5(recv)

    def handle_socks4(self, recv):
        pass

    def handle_socks5(self, recv):
        def exchange_data(remote_peer, local_peer, debug=None):
            """
                exchange ssh channel socket with socks socket
            """
            while True:
                r, _, e = select.select([remote_peer, local_peer],
                                        [], [])
                if remote_peer in r:
                    try:
                        recv = remote_peer.recv(4096)
                    except (socket.error, socket.timeout) as e:
                        raise SocksRemoteException(e.message)
                    try:
                        if local_peer.send(recv) <= 0:
                            break  # remote data --> local client
                    except (socket.error, socket.timeout) as e:
                        raise SocksClientException(e.message)
                if local_peer in r:
                    try:
                        recv = local_peer.recv(4096)
                    except (socket.error, socket.timeout) as e:
                        raise SocksClientException(e.message)
                    try:
                        if remote_peer.send(recv) <= 0:
                            break  # local client --> remote server
                    except (socket.error, socket.timeout) as e:
                        raise SocksRemoteException(e.message)

        def reply_client_bnd(atype, addr, port):
            """
                return success BND protocol return sequences
            """
            self.log('debug', 'atype:%r ,(%s,%d)' % (atype,
                                                     addr,
                                                     port))
            if atype == b'\x01':  # ipv4
                msg = b'\x05\x00\x00\x01%s%s' % (
                    socket.inet_aton(addr),
                    struct.pack(">H", port))
            elif atype == b'\x03':  # domain
                msg = b'\x05\x00\x00\x03%s%s%s' % (
                    struct.pack('>H', len(addr)),
                    addr,
                    struct.pack(">H", port))
            elif atype == b'\x04':  # ipv6
                msg = b'\x05\x00\x00\x04%s%s' % (
                    socket.inet_pton(socket.AF_INET6, addr),
                    struct.pack(">H", port))
            else:
                raise SocksAddressTypeDisabled
            self.log('debug', 'send to client:%r' % msg)
            self.request.send(msg)

        try:
            nmethod, = struct.unpack('b', recv[1:2])
            methods = recv[2:2 + nmethod]
            self.socks5_identifier(methods)
            try:
                _version, _cmd, _, _atype = self.request.recv(4)
                version = bytes([_version])
                cmd = bytes([_cmd])
                atype = bytes([_atype])
            except ValueError as e:
                self.log('error', 'client send error request')
                self.log('debug', '%r' % e)
                raise SocksClientException
            self.log('debug', 'recv msg:%r%r%r%r' % (version,
                                                     cmd,
                                                     _,
                                                     atype))
            if atype == b'\x01':  # ipv4
                addr = socket.inet_ntoa(self.request.recv(4))
            elif atype == b'\x03':  # domain
                addr = self.request.recv(
                    ord(self.request.recv(1)[0]))
            elif atype == b'\x04':  # ipv6
                addr = socket.inet_ntop(socket.AF_INET6,
                                        self.request.recv(16))
            else:
                raise SocksAddressTypeDisabled
            port = struct.unpack('>H', self.request.recv(2))[0]
            self.log('notify', 'client request:(%s,%d)' % (addr, port))

            if cmd == b'\x01':  # connect
                remote_sp, remote_atype = \
                    self.get_s5_conn_sp((addr, port), \
                                        self.request.getpeername(), \
                                        atype)
                # don't get remote socket
                if remote_sp is None:
                    return
                try:
                    bnd_addr, bnd_port = remote_sp.getpeername()
                except socket.error as e:
                    raise SocksRemoteException(e)
                self.log('notify',
                         'connect remote bnd:(%s,%d)' % (bnd_addr,
                                                         bnd_port))
                reply_client_bnd(remote_atype, bnd_addr, bnd_port)
                exchange_data(remote_sp, self.request)
            elif cmd == b'\x02':  # bind
                remote_sp, remote_atype = \
                    self.get_s5_bind_sp((addr, port), \
                                        self.request.getpeername(), \
                                        atype)
                if remote_sp is None:
                    return
                try:
                    bnd_addr, bnd_port = remote_sp.gethostname()
                except socket.error as e:
                    raise SocksRemoteException(e)
                self.log('notify',
                         'bind remote bnd:(%s,%d)' % (bnd_addr,
                                                    bnd_port))
                reply_client_bnd(remote_atype, bnd_addr, bnd_port)
                exchange_data(remote_sp, self.request)
            elif cmd == b'\x03':  # udp
                pass
        except SocksException as e:
            self.log('warning', 'SocksException:%s' % e.message)
#         except socket.error,e:
#             print 'socket.error',e.message


class SocksRemoteRequestHandler(object):
    def connect_handle(self, dst, src, dst_type=b'\x01'):
        try:
            if dst_type in [b'\x01', b'\x03']:
                remote_atype = b'\x01'
                remote = socket.socket(socket.AF_INET,
                                       socket.SOCK_STREAM)
                remote.settimeout(5)
                remote.connect(dst)
            elif dst_type == b'\x04':
                remote_atype = b'\x04'
                remote = socket.socket(socket.AF_INET6,
                                       socket.SOCK_STREAM)
                remote.settimeout(5)
                remote.connect(dst)
            return remote, remote_atype
        except socket.timeout as e:
            print('timeout', dst, src, e.message)
        except socket.error as e:
            print('socket error', dst, src, e.message)
        return None, None

    def bind_handle(self, dst, src, dst_type=b'\x01'):
        return None, None

    def udp_handle(self, dst, src, dst_type=b'\x01'):
        return None, None


class SocksSSHRemoteRequestHandler(SocksRemoteRequestHandler):
    """
    create a ssh channel
    """
    old_conversation = None
    errnum = 0
    reconnectnum = 0

    def __init__(self, domain, username, keyfile, port=22):
        """
        init ssh info
        """
        self.domain = domain
        self.username = username
        self.keyfile = keyfile
        self.port = port

    def get_conversation(self):
        '''
        create a ssh conversation
        '''
        conversation = paramiko.SSHClient()
        conversation.load_system_host_keys()
        ssh_policy = paramiko.WarningPolicy()
        conversation.set_missing_host_key_policy(ssh_policy)
        try:
            conversation.connect(self.domain,
                                 port=self.port,
                                 username=self.username,
                                 key_filename=self.keyfile)
        except socket.gaierror:
            raise SocksRemoteException('Failed connecting to remote server')
        except paramiko.AuthenticationException:
            raise SocksRemoteException('Authentication error')
        except paramiko.BadHostKeyException:
            raise SocksRemoteException('Host key invalid')
        except socket.timeout:
            return self.get_conversation()
        return conversation

    def get_socket(self, conversation, dst, src):
        try:
            trans = conversation.get_transport()
            res = trans.open_channel('direct-tcpip', dst, src)
            res.settimeout(5)
            return res
        except paramiko.ChannelException as e:
            print('retry %s:%d' % dst)
            try:
                trans = conversation.get_transport()
                res = trans.open_channel('direct-tcpip', dst, src)
                res.settimeout(5)
                return res
            except paramiko.ChannelException as e:
                self.errnum += 1
                raise SocksRemoteException(e.message)

    def connect_handle(self, dst, src, dst_type=b'\x01'):
        retry_limit = 5
        if self.old_conversation is None:
            self.old_conversation = self.get_conversation()
        try:
            sp = self.get_socket(self.old_conversation, dst, src)
            self.reconnectnum = 0
        except paramiko.SSHException:
            if not self.reconnectnum > retry_limit:
                self.reconnectnum += 1
                self.old_conversation = self.get_conversation()
                return self.connect_handle(dst, src, dst_type)
            else:
                raise SocksRemoteException(
                    'Failed after {s} retries'.format(s=retry_limit))
        return sp, b'\x01'


class SocksServer(socketserver.TCPServer):
    def __init__(self,
                 server_address,
                 RequestHandlerClass,
                 TunnelHandler,
                 bind_and_activate=True):
        if isinstance(TunnelHandler, SocksRemoteRequestHandler):
            self.socks = TunnelHandler
        else:
            raise SocksRemoteException
        try:
            socketserver.TCPServer.__init__(self, server_address,
                                            RequestHandlerClass,
                                            bind_and_activate)
        except socket.error as e:
            if e.errno == 98:
                print('Address already in use, Socks service start failed')
            else:
                print(e)
            exit()


class ThreadingSocksServer(socketserver.ThreadingMixIn, SocksServer):
    pass


class ForkingSocksServer(socketserver.ForkingMixIn, SocksServer):
    pass


class SocksOverSSH:
    def __init__(self, remote_addr, remote_port=22,
                 username=None, keyfile=None,
                 local_addr='127.0.0.1', local_port=0):
        self._remote_addr = remote_addr
        self._remote_port = remote_port
        self._username = username
        self._keyfile = keyfile
        self._local_addr = local_addr
        self._local_port = local_port

    @classmethod
    def batch_create(cls, configs, run=False):
        ret = [
            cls(x['remote_addr'], remote_port=x['remote_port'],
                username=x['username'], keyfile=x['keyfile'],
                local_addr=x.get('local_addr', '127.0.0.1'),
                local_port=x.get('local_port', 0)
                ) for x in configs
        ]
        if run:
            for x in ret:
                x.run()
        return ret

    def get_local_addr(self):
        return self._server.server_address

    def run(self):
        sshtunnel = SocksSSHRemoteRequestHandler(
            self._remote_addr, self._username, self._keyfile, self._remote_port)
        self._server = ThreadingSocksServer(
            (self._local_addr, self._local_port),
            SocksRequestHandler,
            sshtunnel
        )
        server_thread = threading.Thread(target=self._server.serve_forever)
        server_thread.daemon = True
        server_thread.start()

    def stop(self):
        self._server.shutdown()
        self._server = None
