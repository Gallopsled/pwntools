#!/usr/bin/env python
from pwn import b64d, write
import json, sys

if __name__ == '__main__':
    from Crypto.Util import number
    from pbpoke import Encryption
    import requests

    if len(sys.argv) < 3 or 4 < len(sys.argv):
        print('- Download an encrypted file made by pbpoke - ')
        print('Usage: %s identifier password [filename]' % sys.argv[0])
        sys.exit(1)

    identifier = b64d(sys.argv[1]).encode('hex')
    password = sys.argv[2]
    filename = sys.argv[3] if len(sys.argv) == 4 else None

    try:
        req = requests.get('https://api.github.com/gists/' + identifier)
    except Exception as e:
        print('Unable to download from Github.')
        print(str(e))
        sys.exit(1)

    if req.status_code != 200:
        print('Unable to download from github, debug information follows')
        print(req.text)
        sys.exit(1)

    try:
        data = b64d(json.loads(req.text)['files']['data']['content'])
    except Exception as e:
        print('Unpacking data from Github failed.')
        print(str(e))
        sys.exit(1)

    cipher = Encryption(password)
    decrypted = cipher.decrypt(data)

    try:
        if filename is None:
            sys.stdout.write(decrypted)
        else:
            write(filename, decrypted)
    except Exception as e:
        print("Unable to write data to file '%s'" % filename)
        print(str(e))
        sys.exit(1)
