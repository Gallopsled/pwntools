import urllib2
import cookielib
import urllib
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


    def login(self, url, username, password):
        passman = urllib2.HTTPPasswordMgrWithDefaulRealm()
        passman.add_password(None, url, username, password)
        authhandler  = urllib2.HTTPBasicAuthHandler(passman)
        self.opener.add_handler(authhandler)
        self.open(url)


    def open(self, url):
        try:
            url_fd  = self.opener.open(url)
        except:
            print "Something went wrong, site not fetched correctly"
            return
        self.headers = url_fd.headers.dict
        self.html    = url_fd.read()            


    def add_uaheaders(self):
        self.opener.addheaders = [('User-agent', ua.randomua())]
        return self.opener.addheaders


