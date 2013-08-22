#!/usr/bin/env python
from pwn import b64, read, unhex
import json, sys

class Encryption:
    def __init__(self, password):
        from Crypto.Hash import HMAC, SHA256
        from Crypto.Protocol.KDF import PBKDF2

        raw_key = PBKDF2(password, 'DANGERZONE', count=1000000) # ONLY HMAC-SHA1
        key_parts = HMAC.new(raw_key, msg='keys', digestmod=SHA256).digest()
        self.enc_key = key_parts[:16]
        self.mac_key = key_parts[16:]

    def encrypt(self, data):
        from Crypto.Cipher import AES
        from Crypto.Hash import HMAC, SHA512
        from Crypto.Util import Counter, number

        initial_value = number.getRandomInteger(128)
        counter = Counter.new(128, initial_value=initial_value)
        cipher = AES.new(self.enc_key, AES.MODE_CTR, counter=counter)
        encrypted = cipher.encrypt(data)

        protected_data = ('%032x' % initial_value) + encrypted
        mac = HMAC.new(self.mac_key, msg=protected_data, digestmod=SHA512)
        digest = mac.digest()

        return digest + protected_data

    def decrypt(self, data):
        from Crypto.Cipher import AES
        from Crypto.Hash import HMAC, SHA512
        from Crypto.Util import Counter

        authentication = data[:64]
        protected_data = data[64:]

        mac = HMAC.new(self.mac_key, msg=protected_data, digestmod=SHA512)
        digest = mac.digest()

        if digest != authentication:
            print('DANGER: File has been tampered with')
            sys.exit(1)

        initial_value = long(protected_data[:32], 16)
        encrypted = protected_data[32:]

        counter = Counter.new(128, initial_value=initial_value)
        cipher = AES.new(self.enc_key, AES.MODE_CTR, counter=counter)
        return cipher.decrypt(encrypted)

if __name__ == '__main__':
    from Crypto.Util import number
    import requests

    if len(sys.argv) < 2 or 3 < len(sys.argv):
        print('- Indirect and encrypted poke through pastebins -')
        print('Usage: %s password [filename]' % sys.argv[0])
        sys.exit(1)

    password = sys.argv[1]
    filename = sys.argv[2] if len(sys.argv) == 3 else None

    data = read(filename) if filename is not None else sys.stdin.read()

    cipher = Encryption(password)
    upload_data = b64(cipher.encrypt(data))

    try:
        upload = {'public':False, 'files':{'data':{'content':upload_data}}}
        req = requests.post('https://api.github.com/gists', data=json.dumps(upload))
    except Exception as e:
        print('Unable to upload data to Github.')
        print(str(e))
        sys.exit(1)

    if req.status_code != 201:
        print('Unable to upload to github, debug information follows')
        print(req.text)
        sys.exit(1)

    try:
        res = json.loads(req.text)
        file_id = res['url'].split('/')[-1]
    except Exception as e:
        print('Unable to load JSON response from Github.')
        print(str(e))
        sys.exit(1)

    identifier = b64(unhex(file_id))
    print('Identifier: %s' % identifier)
    print('Password: %s' % password)
