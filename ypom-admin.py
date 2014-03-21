#!/usr/bin/env python
# -*- coding: utf-8 -*-

import time
import json
from base64 import b32encode, b64encode, b64decode
import os
import sys
import binascii
import getpass
import warnings

__author__    = 'Christoph Krey <krey.christoph()gmail.com>'
__copyright__ = 'Copyright 2014 Christoph Krey'
__license__   = """Eclipse Public License - v 1.0 (http://www.eclipse.org/legal/epl-v10.html)"""

with warnings.catch_warnings():
    warnings.simplefilter('ignore')

    import nacl.utils
    import nacl.secret
    import nacl.hash
    import nacl.signing
    from nacl.public import PublicKey, PrivateKey, Box
    from nacl.encoding import Base64Encoder

def storelogin(identifier, passwordstring, host, port, auth, tls):

    logindata = {
        'user'		: identifier,
        'passwd'	: passwordstring,
        'host'		: host,
        'port'		: port,
        'auth'		: auth
        'tls'		: tls
    }

    clear_text =  json.dumps(logindata)

    nonce = nacl.utils.random(Box.NONCE_SIZE)

    box = Box(me_seckey, user_pubkey)
    encrypted = box.encrypt(clear_text, nonce)

    signed = me_sigkey.sign(encrypted, encoder=Base64Encoder);

    data = {
        'id'		: me_identifier,
        'verkey'	: me_verkey64,
        'pubkey'	: me_pubkey64,
        'login'		: signed
    }

    path = '%s.ypom' % identifier
    fd = open(path, 'w')
    fd.write(json.dumps(data))
    fd.close()

def storeacl(identifier):

    path = '%s.acl' % identifier

    fd = open(path, 'w')

    fd.write('\n')
    fd.write('###user %s\n' % identifier)
    fd.write('user %s\n' % identifier)
    fd.write('topic ypom/+/+\n')

    fd.close()

try:
    me_file = open('me.creds', 'r')

    pw = os.getenv("YPOMCREDSPW")
    if pw is None:
        try:
            pw = os.getenv("YPOMCREDSPW", getpass.getpass('Enter password to decrypt private key: '))
        except KeyboardInterrupt:
            sys.exit(2)

    h = nacl.hash.sha256(pw)

    key = binascii.unhexlify(h)

    box = nacl.secret.SecretBox(key)

    message = me_file.read().rstrip()
    encrypted_data = binascii.unhexlify(message)

    plaintext = box.decrypt(encrypted_data)

    me_data = json.loads(plaintext)
    me_identifier = me_data['id']
    me_pubkey64 = me_data['pubkey']
    me_verkey64 = me_data['verkey']
    me_seckey64 = me_data['seckey']
    me_sigkey64 = me_data['sigkey']

    if me_seckey64 is not None:
        me_seckey = PrivateKey(me_seckey64, encoder=Base64Encoder)

    if me_pubkey64 is not None:
        me_pubkey = PublicKey(me_pubkey64, encoder=Base64Encoder)

    if me_sigkey64 is not None:
        me_sigkey = nacl.signing.SigningKey(me_sigkey64, encoder=Base64Encoder)

    if me_verkey64 is not None:
        me_verkey = nacl.signing.VerifyKey(me_verkey64, encoder=Base64Encoder)


except Exception, e:
    print "Cannot load `me.creds': %s" % (str(e))
    sys.exit(1)

try:
    host_file = open('host.info', 'r')
    host = host_file.read()
    hostdata = json.loads(host)
    host_host = hostdata['host']
    host_port = hostdata['port']
    host_auth = hostdata['auth']
    host_tls = hostdata['tls']

except Exception, e:
    print "Cannot load `host.info': %s" % (str(e))
    sys.exit(1)

try:
    user_file = open('newuser.ypom', 'r')
    user = user_file.read()
    userdata = json.loads(user)
    user_identifier = userdata['id']
    user_pubkey64 = userdata['pubkey']
    if user_pubkey64 is not None:
        user_pubkey = PublicKey(user_pubkey64, encoder=Base64Encoder)

    user_passwd = nacl.utils.random(32);
    user_passwdstring = b32encode(user_passwd)

    os.system ('(echo "%s"; echo "%s") | mosquitto_passwd -c %s.passwd %s >/dev/null' %
	(user_passwdstring, user_passwdstring, user_identifier, user_identifier))

    storeacl(user_identifier)

    storelogin(user_identifier, user_passwdstring, host_host, host_port, host_auth, host_tls)

    print "Done for identifier:%s" % user_identifier

except Exception, e:
    print "Cannot load `newuser.ypom': %s" % (str(e))
    sys.exit(1)

