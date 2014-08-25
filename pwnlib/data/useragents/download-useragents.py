#!/usr/bin/env python2
"""
Script for downloading lists of user agent strings
"""

from bs4 import BeautifulSoup
import re, urllib
from pwn import *

uas = set()

def getxml(url):
    f = urllib.urlopen(url)
    xml = f.read()
    f.close()
    return xml

log.waitfor('Fetching from from http://www.useragentstring.com')
html = getxml('http://www.useragentstring.com/pages/All/')
soup = BeautifulSoup(html)
log.done_success()

log.waitfor('Parsing list')
liste = soup.select('#liste a')
for a in liste:
    href = a.get('href')
    if not href or href[0] != '/':
        continue
    m = re.match('More (.+) user agents strings -->>', a.string)
    if m:
        target = m.group(1)
        log.waitfor('Fetching additional user agents for %s' % target)
        html = getxml('http://www.useragentstring.com' + href)
        soup = BeautifulSoup(html)
        subliste = soup.select('#liste a')
        for a in subliste:
            ua = a.string.strip()
            try:
                ua = ua.decode('utf-8')
            except UnicodeEncodeError:
                continue
            uas.add(ua)
        log.done_success()
    else:
        uas.add(a.string.strip())
log.done_success()


log.waitfor('Fetching from from http://techpatterns.com')
xml = getxml('http://techpatterns.com/downloads/firefox/useragentswitcher.xml')
soup = BeautifulSoup(xml)
log.done_success()

def loop(xml):
    for item in xml:
        if item.name == 'folder':
            if item['description'] != 'UA List :: About':
                loop(item)
        elif item.name == 'useragent':
            uas.add(item['useragent'].strip())

log.waitfor('Parsing list')
loop(soup.body.useragentswitcher)
log.done_success()


log.waitfor('Fetching from from http://www.user-agents.org')

xml = getxml('http://www.user-agents.org/allagents.xml')
soup = BeautifulSoup(xml)
log.done_success()

log.waitfor('Parsing list')
for item in soup.body.__getattr__('user-agents'):
    if item.name == 'user-agent':
        ua = item.select('string')[0].string.strip()
        try:
            ua = ua.decode('utf-8')
        except UnicodeEncodeError:
            continue
        uas.add(ua)
log.done_success()

log.info('Fetched %d user agents' % len(uas))

write('useragents.txt', ''.join(sorted(ua + '\n' for ua in uas)))
