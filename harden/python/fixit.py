from config import *
import re, subprocess, os, sys


with open('whitelist', 'w') as f:
    f.write('')

while True:
    try:
        os.unlink("/tmp/python_error_log")
    except:
        pass
    try:
        # p = subprocess.check_call('gnome-terminal -e \'sh -c "PYTHONPATH=$PYTHONPATH:/usr/share/pyshared ~/src/Python-2.7.3/python %s"\'' % sys.argv[1], shell = True)
        p = subprocess.check_call('gnome-terminal -e \'sh -c "PYTHONPATH=/usr/share/pyshared ~/src/Python-2.7.3/python %s"\'' % sys.argv[1], shell = True)
    except subprocess.CalledProcessError:
        pass

    try:
        with open('whitelist') as f:
            whitelist = f.read().strip().split('\n')
        with open('/tmp/python_error_log') as f:
            new = sorted(set(f.read().strip().split('\n')))

        new = [s for s in new if s not in whitelist]

        if not new:
            print "No new"
            continue

        whitelist += new
        print ' '.join(new)

        with open('whitelist', 'w') as f:
            f.write('\n'.join(whitelist).strip())
    except IOError as e:
        print e

