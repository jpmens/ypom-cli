#!/usr/bin/env python

import warnings
import binascii
import sys
import os
import stat
from base64 import b64encode, b64decode, b32encode
import json
import getpass

with warnings.catch_warnings():
    warnings.simplefilter('ignore')

    import nacl.utils
    import nacl.secret
    import nacl.hash
    #CK signing
    import nacl.signing
    from nacl.public import PrivateKey, PublicKey, Box
    from nacl.encoding import HexEncoder, Base64Encoder, Base32Encoder

#CK id sigkey + verkey
def store(id, pw, seckey, pubkey, sigkey, verkey):

    path = 'me.creds'
    data = {
        'id'		: id,
        'seckey'	: b64encode(seckey),
        'pubkey'	: b64encode(pubkey),
        'sigkey'	: b64encode(sigkey),
        'verkey'	: b64encode(verkey)
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
    fd.write(binascii.hexlify(encrypted))
    fd.close()
    os.chmod(path, stat.S_IREAD)

    ypomdata = {
        'id'		: id,
        'pubkey'	: b64encode(pubkey),
        'verkey'	: b64encode(verkey)
    }
    fd = open('me.ypom', 'w')
    fd.write(json.dumps(ypomdata))
    fd.close()



if __name__ == '__main__':
    if len(sys.argv) != 1:
        print "Usage: %s" % sys.argv[0]
        sys.exit(1)

    pw1 = getpass.getpass('Enter password to protect private key: ')
    pw2 = getpass.getpass('Re-enter same password: ')

    if pw1 != pw2:
        print "Passwords don't match. Abort."
        sys.exit(1)

    secret_key = PrivateKey.generate()
    public_key = secret_key.public_key

    #CK add signing
    signing_key = nacl.signing.SigningKey.generate()
    verify_key = signing_key.verify_key

    #CK add id generation
    hash = nacl.hash.sha256(public_key.__bytes__())
    #print "hash: %s" % hash 

    hashbin = b64decode(hash)
    #print "hashbin: %s" % hashbin
 
    hash32 = b32encode(hashbin)
    #print "hash32: %s" % hash32 

    id = hash32[:8]
    print "id: %s" % id 

    store(id, pw1, secret_key.__bytes__(), public_key.__bytes__(), signing_key.__bytes__(), verify_key.__bytes__())

