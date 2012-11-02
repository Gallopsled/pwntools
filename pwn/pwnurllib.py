import urllib2
import cookielib
import urllib
import useragents as ua

class pwnurllib(object):
    def __init__(self, ua=True):
        self.jar           = cookielib.CookieJar()
        self.cookieHandler = urllib2.HTTPCookieProcessor(self.jar)
        self.opener   = urllib2.build_opener(self.cookieHandler)
        self.url_fd   = None
        self.headers  = None

    def login(self, url, username, password):
        passman = urllib2.HTTPPasswordMgrWithDefaulRealm()
        passman.add_password(None, url, username, password)
        authhandler  = urllib2.HTTPBasicAuthHandler(passman)
        self.opener.add_handler(authhandler)
        return self.open(url)


    def open(self, url):
        self.url_fd = self.opener.open(url)
        self.headers = self.url_fd.headers
        return self.url_fd


    def get_header(self):
        if self.headers == None:
            return False
        return self.headers


    def add_uaheaders(self):
        self.opener.addheaders = [('User-agent', ua.randomua())]
        return self.opener.addheaders


