#!/usr/bin/env python2
"""
Script for downloading lists of user agent strings
"""
import os
import re
import urllib

from bs4 import BeautifulSoup

from pwn import *

uas = set()
if os.path.isfile('useragents.txt'):
    with open('useragents.txt') as fd:
        for line in fd:
            if line:
                uas.add(line.rstrip())

def getxml(url):
    f = urllib.urlopen(url)
    xml = f.read()
    f.close()
    return xml

with log.waitfor('Fetching from from http://www.useragentstring.com') as l:
    html = getxml('http://www.useragentstring.com/pages/All/')
    soup = BeautifulSoup(html)
    l.success()

with log.waitfor('Parsing list') as l:
    liste = soup.select('#liste a')
    for a in liste:
        href = a.get('href')
        if not href or href[0] != '/':
            continue
        m = re.match('More (.+) user agents strings -->>', a.string)
        if m:
            target = m.group(1)
            with log.waitfor('Fetching additional user agents for %s' % target) as l:
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
                l.success()
        else:
            uas.add(a.string.strip())
    l.success()

with log.waitfor('Fetching from from http://techpatterns.com') as l:
    xml = getxml('http://techpatterns.com/downloads/firefox/useragentswitcher.xml')
    soup = BeautifulSoup(xml)
    l.success()

def loop(xml):
    for item in xml:
        if item.name == 'folder':
            if item['description'] != 'UA List :: About':
                loop(item)
        elif item.name == 'useragent':
            uas.add(item['useragent'].strip())

with log.waitfor('Parsing list') as l:
    loop(soup.body.useragentswitcher)
    l.success()

with log.waitfor('Fetching from from http://www.user-agents.org') as l:
    xml = getxml('http://www.user-agents.org/allagents.xml')
    soup = BeautifulSoup(xml)
    l.success()

with log.waitfor('Parsing list') as l:
    for item in soup.body.__getattr__('user-agents'):
        if item.name == 'user-agent':
            ua = item.select('string')[0].string.strip()
            try:
                ua = ua.decode('utf-8')
            except UnicodeEncodeError:
                continue
            uas.add(ua)
    l.success()

log.info('Fetched %d user agents' % len(uas))

write('useragents.txt', ''.join(sorted(ua + '\n' for ua in uas)))
