#!/usr/bin/env python

import warnings
import binascii
import sys
import os
import stat
from base64 import b64encode
import json
import getpass

with warnings.catch_warnings():
    warnings.simplefilter('ignore')

    import nacl.utils
    import nacl.secret
    import nacl.hash
    from nacl.public import PrivateKey, PublicKey, Box
    from nacl.encoding import HexEncoder, Base64Encoder

def store(username, pw, sk, pk):

    path = 'me.creds'
    data = {
        'username'  : username,
        'sk'        : b64encode(sk),
        'pk'        : b64encode(pk),
    }

    if os.path.exists(path):
        print "file %s exists: abort" % path
        sys.exit(1)

    h = nacl.hash.sha256(pw)
    key = binascii.unhexlify(h)

    box = nacl.secret.SecretBox(key)
    message = json.dumps(data)

    nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)

    encrypted = box.encrypt(message, nonce)

    fd = open(path, 'w')
    fd.write("%s\n" % binascii.hexlify(encrypted))
    fd.close()
    os.chmod(path, stat.S_IREAD)


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print "Usage: username"
        sys.exit(1)

    username = sys.argv[1]

    pw1 = getpass.getpass('Enter password to protect private key: ')
    pw2 = getpass.getpass('Re-enter same password: ')

    if pw1 != pw2:
        print "Passwords don't match. Abort."
        sys.exit(1)

    secret_key = PrivateKey.generate()
    public_key = secret_key.public_key

    store(username, pw1, secret_key.__bytes__(), public_key.__bytes__())

