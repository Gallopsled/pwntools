import os
import sys
import time
import ctypes
import random
import string
import struct
import socket
import logging
import threading

from windows import *
import windows
import windows.winobject
import windows.winproxy
import windows.native_exec.nativeutils
import windows.generated_def as gdef
from windows.generated_def.winstructs import *
import windows.native_exec.simple_x64 as x64
import windows.debug




CreatePipePrototype = gdef.WINFUNCTYPE(gdef.BOOL, gdef.PHANDLE, gdef.PHANDLE, gdef.LPSECURITY_ATTRIBUTES, gdef.DWORD)
CreatePipeParams = ((1, 'hReadPipe'), (1, 'hReadPipe'), (1, 'lpPipeAttributes'), (1, 'nSize'))
PeekNamedPipePrototype = gdef.WINFUNCTYPE(gdef.BOOL, gdef.HANDLE, gdef.LPVOID, gdef.DWORD, gdef.LPDWORD, gdef.LPDWORD,
                                          gdef.LPDWORD)
PeekNamedPipeParams = (
(1, 'hNamedPipe'), (1, 'lpBuffer'), (1, 'nBufferSize'), (1, 'lpBytesRead'), (1, 'lpTotalBytesAvail'),
(1, 'lpBytesLeftThisMessage'))

class Pipe(object):
    """Windows pipe support"""

    def __init__(self, bInheritHandle=1):
        attr = SECURITY_ATTRIBUTES()
        attr.lpSecurityDescriptor = 0
        attr.bInheritHandle = bInheritHandle
        attr.nLength = ctypes.sizeof(attr)
        self._rpipe, self._wpipe = self.CreatePipe(attr)
        self._rh = [h for h in windows.current_process.handles if h.value == self._rpipe][0]
        self._wh = [h for h in windows.current_process.handles if h.value == self._wpipe][0]

        self.timeout = 500  # ms
        self.tick = 40  # ms

    @windows.winproxy.Kernel32Proxy('PeekNamedPipe', deffunc_module=sys.modules[__name__])
    def PeekNamedPipe(self, hNamedPipe):
        lpTotalBytesAvail = gdef.DWORD()
        self.PeekNamedPipe.ctypes_function(hNamedPipe, None, 0, None, lpTotalBytesAvail, None)
        return lpTotalBytesAvail.value

    @windows.winproxy.Kernel32Proxy('CreatePipe', deffunc_module=sys.modules[__name__])
    def CreatePipe(self, lpPipeAttributes=None, nSize=0):
        hReadPipe = gdef.HANDLE()
        hWritePipe = gdef.HANDLE()
        self.CreatePipe.ctypes_function(hReadPipe, hWritePipe, lpPipeAttributes, nSize)
        return hReadPipe.value, hWritePipe.value

    def get_handle(self, mode='r'):
        """get_handle(mode = 'r') returns the 'r'ead / 'w'rite HANDLE of the pipe"""
        if mode and mode[0] == 'w':
            return self._wpipe
        return self._rpipe

    def __del__(self):
        if windows is not None:
            windows.winproxy.CloseHandle(self._rpipe)
            windows.winproxy.CloseHandle(self._wpipe)
        else:
            pass

    def number_of_clients(self):
        return max(self._rh.infos.HandleCount, self._wh.infos.HandleCount)

    def select(self):
        """select() returns the number of bytes available to read on the pipe"""
        return self.PeekNamedPipe(self._rpipe)

    def _read(self, size):
        if size == 0:
            return b""
        buffer = ctypes.create_string_buffer(size)
        windows.winproxy.ReadFile(self._rpipe, buffer)
        return buffer.raw

    def read(self, size):
        """read(size) returns the bytes read on the pipe (returned length <= size)"""
        if self.select() < size:
            elapsed = 0
            while elapsed <= self.timeout and self.select() < size:
                time.sleep(float(self.tick) / 1000)
                elapsed += self.tick
        return self._read(min(self.select(), size))

    def write(self, buffer):
        """write(buffer) sends the buffer on the pipe"""
        windows.winproxy.WriteFile(self._wpipe, buffer)