
#  * Portions of this file are derived from pwntools-tube-websocket by frankli0324
#  * under the MIT License. 
#  * 
#  * Copyright (c) frankli0324.
#  * https://gist.github.com/frankli0324/795162a14be988a01e0efa0531f7ac5a
#  *
#  * Permission is hereby granted, free of charge, to any person obtaining a copy
#  * of this software and associated documentation files (the "Software"), to deal
#  * in the Software without restriction, including without limitation the rights
#  * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#  * copies of the Software, and to permit persons to whom the Software is
#  * furnished to do so, subject to the following conditions:
#  * 
#  * The above copyright notice and this permission notice shall be included in all
#  * copies or substantial portions of the Software.
from __future__ import absolute_import
from __future__ import division
from websocket import WebSocket, ABNF, WebSocketException, WebSocketTimeoutException

from pwnlib.tubes.tube import tube


class wstube(tube):
    """
    A basic websocket interface that wrapped as a tube.

    Arguments:
        url (str): The websocket server's URL to connect to.
        headers (dict): The same headers as the websocket protocol.
        
    Examples:
        
        >>> ws = wstube('wss://echo.websocket.events')
        >>> ws.recv()
        b'echo.websocket.events sponsored by Lob.com'
        >>> for i in range(3):
        ...     ws.send(b'test')
        ...     print(ws.recv(2))
        ...     print(ws.recv(2))
        b'te'
        b'st'
        b'te'
        b'st'
        b'te'
        b'st'
        >>> ws.sendline(b'test')
        >>> print(ws.recv())
        b'test\\n'
        >>> ws.send(b'12345asdfg')
        >>> print(ws.recvregex(b'[0-9]{5}'))
        b'12345'
        >>> print(ws.recv())
        b'asdfg'
        >>> ws.close()
    """
    def __init__(self, url, headers=None, *args, **kwargs):
        if headers is None:
            headers = {}
        super(wstube, self).__init__(*args, **kwargs)
        self.closed = False
        self.sock = WebSocket()
        self.url = url
        self.sock.connect(url, header=headers)
        
        
    def recv_raw(self, numb):
        if self.closed:
            raise EOFError

        while True:
            try:
                data = self.sock.recv()
                if isinstance(data, str):
                    data = data.encode()
                break
            except WebSocketTimeoutException:
                return None
            except WebSocketException:
                self.shutdown("recv")
                raise EOFError

        if not data:
            self.shutdown()
            raise EOFError('Recv Error')

        return data
    
    def send_raw(self, data):
        if self.closed:
            raise EOFError

        try:
            self.sock.send_binary(data)
        except WebSocketException as e:
            self.shutdown()
            raise EOFError('Send Error')

    def settimeout_raw(self, timeout):
        if getattr(self, 'sock', None):
            self.sock.settimeout(timeout)

    def connected_raw(self, direction):
        try:
            self.sock.ping()
            opcode, data = self.sock.recv_data(True)
            return opcode == ABNF.OPCODE_PONG
        except:
            return False

    def close(self):
        if not getattr(self, 'sock', None):
            return

        self.closed = True

        self.sock.close()
        self.sock = None
        self._close_msg()

    def _close_msg(self):
        self.info('Closed connection to %s', self.url)

    def shutdown_raw(self, direction):
        if self.closed:
            return

        self.closed = True
        self.sock.shutdown()