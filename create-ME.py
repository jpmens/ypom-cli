#!/usr/bin/env python

import warnings
import binascii
import sys
import os
import stat
from base64 import b64encode
import json

with warnings.catch_warnings():
    warnings.simplefilter('ignore')

    import nacl.utils
    from nacl.public import PrivateKey, PublicKey, Box
    from nacl.encoding import HexEncoder, Base64Encoder

def store(username, sk, pk):

    path = 'me.json'
    data = {
        'username'  : username,
        'sk'        : b64encode(sk),
        'pk'        : b64encode(pk),
    }

    if os.path.exists(path):
        print "file %s exists: abort" % path
        sys.exit(1)

    fd = open(path, 'w')
    fd.write("%s\n" % json.dumps(data))
    fd.close()
    os.chmod(path, stat.S_IREAD)


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print "Usage: username"
        sys.exit(1)

    username = sys.argv[1]

    secret_key = PrivateKey.generate()
    public_key = secret_key.public_key

    store(username, secret_key.__bytes__(), public_key.__bytes__())

