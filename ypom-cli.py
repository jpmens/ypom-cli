#!/usr/bin/env python
# -*- coding: utf-8 -*-

import paho.mqtt.client as paho   # pip install paho-mqtt
import sys
import ssl
import time
import json
import readline
from base64 import b32encode, b64encode, b64decode
import binascii
import getpass
import os
import warnings
import imghdr

__author__    = 'Jan-Piet Mens <jpmens()gmail.com>'
__copyright__ = 'Copyright 2014 Jan-Piet Mens'
__license__   = """Eclipse Public License - v 1.0 (http://www.eclipse.org/legal/epl-v10.html)"""

with warnings.catch_warnings():
    warnings.simplefilter('ignore')

    import nacl.utils
    import nacl.secret
    import nacl.hash
    import nacl.signing
    from nacl.public import PublicKey, PrivateKey, Box
    from nacl.encoding import Base64Encoder

class Completer(object):

    def __init__(self, users):
        self.users = []
        if users is not None:
            self.users = sorted(users)

    def add(self, user):
        # print "Adding [%s] to completer" % user
        self.users.append(user)

    def complete(self, text, state):
        response = None
        if state == 0:
            if text:
                self.matches = [s
                                for s in self.users
                                if s and s.startswith(text)]
            else:
                self.matches = self.users[:]

        # Return the state'th item from the match list
        try:
            response = self.matches[state]
            response = response + ': '
        except IndexError:
            response = None
        return response

completer = Completer(None)

def topicname(toid, fromid):
    prefix = 'ypom'

    # to/from
    topic = '%s/%s/%s' % ( prefix, toid, fromid)
    return topic

class User(object):

    def __init__(self, identifier, pubkey64, verkey64, seckey64=None, sigkey64=None):
        self.identifier = identifier
        self.seckey = None
        self.seckey64 = None
        self.pubkey = None
        self.pubkey64 = None
        self.sigkey = None
        self.sigkey64 = None
        self.verkey = None
        self.verkey64 = None

        if pubkey64 is not None:
            self.pubkey = PublicKey(pubkey64, encoder=Base64Encoder)
            self.pubkey64 = pubkey64

        if seckey64 is not None:
            self.seckey64 = seckey64
            self.seckey = PrivateKey(seckey64, encoder=Base64Encoder)

        if verkey64 is not None:
            self.verkey = nacl.signing.VerifyKey(verkey64, encoder=Base64Encoder)
            self.verkey64 = verkey64

        if sigkey64 is not None:
            self.sigkey64 = sigkey64
            self.sigkey = nacl.signing.SigningKey(sigkey64, encoder=Base64Encoder)

    def send(self, msg, content_type=None):
        ''' Send the clear text 'msg' to this user '''

        box = Box(me.seckey, self.pubkey)

        if content_type == None:
            content_type = 'text/plain; charset:"utf-8"'

        data = {
            "_type" : "msg",
            "timestamp" : time.time(),
            "content" : b64encode(msg),
            "content-type" : content_type,
        }
        clear_text =  json.dumps(data)

        # This is a nonce, it *MUST* only be used once, but it is not considered
        #   secret and can be transmitted or stored alongside the ciphertext. A
        #   good source of nonce is just 24 random bytes.
        nonce = nacl.utils.random(Box.NONCE_SIZE)

        # print "NONCE = ", binascii.hexlify(nonce)

        encrypted = box.encrypt(clear_text, nonce)

        signed = me.sigkey.sign(encrypted, encoder=Base64Encoder);

        #   to/from
        topic = topicname(self.identifier, me.identifier)

        mqttc.publish(topic, signed, qos=2, retain=False)

    def decrypt(self, mqttpayload):

        image_types = {
            'image/png'         : 'png',
            'image/jpeg'        : 'jpg',
            'image/jpg'         : 'jpg',
            'image/gif'         : 'gif',
        }

	messagehex = b64decode(mqttpayload)
	message = nacl.signing.SignedMessage(messagehex)
	self.verkey.verify(message)
	#print "verified"

        box = Box(me.seckey, self.pubkey)
	
        #
        #CK don't like the literal 64, but I don't know where to get the symbol
        #
        plaintext = box.decrypt(message[64:])
	#print "decrypted"
        message_data = json.loads(plaintext)
	#print "json out"

        if '_type' in message_data:
            tst = message_data['timestamp']
            time_str = time.strftime('%H:%M', time.localtime(float(tst)))
            if message_data.get('_type') == 'ack':
                return time_str, "ACK"
            if message_data.get('_type') == 'see':
                return time_str, "SEE"
            if message_data.get('_type') == 'msg':
                message = b64decode(message_data['content'])

                content_type = message_data.get('content-type', 'unknown')
                if content_type in image_types:
                    extension = image_types[content_type]
                    filename = '%s-%s.%s' % (self.identifier, time.time(), extension)
                    try:
                        fd = open(filename, "wb")
                        fd.write(message)
                        fd.close()
                    except Exception, e:
                        return time_str, "Cannot create file %s: %s" % (filename, str(e))


                    return time_str, "<Incoming file stored as %s>" % filename


                if message_data.get('content-type') != u'text/plain; charset:"utf-8"':
                    message = 'Unsupported content-type: %s' % message_data.get('content-type')
                return time_str, message

userlist = {}   # indexed by user identifier


def on_connect(mosq, userdata, rc):
    mysub = "ypom/%s/+" % me.identifier
    print "subscribing to >%s< " % mysub
    #
    #CK: I don't understand why next line throws an error... use constant for the time being
    #
    #mqttc.subscribe(mysub, 2)
    mqttc.subscribe("ypom/PPD7PXPG/+", 2)

def on_message(mosq, userdata, msg):
    # print "%s (qos=%s, r=%s) %s" % (msg.topic, str(msg.qos), msg.retain, str(msg.payload))

    topic = msg.topic
    payload = msg.payload

    if paho.topic_matches_sub('ypom/+/+', topic):
        prefix, toidentifier, fromidentifier = topic.split('/', 3)

        try:
            u_from = userlist[fromidentifier]
            u_to = userlist[toidentifier]

            tst, msg = u_from.decrypt(msg.payload)
            msg = msg.decode('utf-8')
            print u'%s: %s  [%s]' % (u_from.identifier, msg, tst)
        except:
            raise
            print "SOMETHING WRONG"

def on_publish(mosq, userdata, mid):
    #print("published mid: "+str(mid))
    pass

def on_subscribe(mosq, userdata, mid, granted_qos):
    #print("Subscribed: "+str(mid)+" "+str(granted_qos))
    pass

def on_disconnect(mosq, userdata, rc):
    print "OOOOPS! disconnect"

def quit():
    mqttc.loop_stop()
    mqttc.disconnect()
    sys.exit(0)

def input_loop():
    line = ''
    print "Use TAB-completion for identifier. (quit to exit)"
    while line != 'quit':
        to = message = None
        try:
            line = raw_input("%s> " % me.identifier)
        except KeyboardInterrupt:
            quit()

        try:
            to, message = line.split(':', 2)
            message = message.lstrip().rstrip()
        except ValueError:
            try:
                to, message = line.split(' ', 1)
                message = message.lstrip().rstrip()
            except:
                continue
        if to not in userlist:
            print "user %s unknown" % to
            continue
        u = userlist[to]

        content_type = None
        if message.startswith('<'):
            path = message[1:].lstrip().rstrip()
            try:
                fd = open(path, 'rb')
                message = fd.read()
                fd.close()
                content_type = 'image/png'
                try:
                    content_type = 'image/%s' % imghdr.what(path)
                except:
                    pass
            except Exception, e:
                print "Cannot open file %s for reading: %s" % (path, str(e))
                continue

        u.send(message, content_type)

readline.set_completer(completer.complete)

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
    me = User(me_data.get('id'), me_data.get('pubkey'), me_data.get('verkey'), me_data.get('seckey'), me_data.get('sigkey'))
    userlist[me_data.get('id')] = me;
    print "I am:>%s<" % me.identifier 

except Exception, e:
    print "Cannot load `me.creds': %s" % (str(e))
    sys.exit(1)

try:
    user_file = open('users', 'r')
    for user in user_file:
        userdata = json.loads(user)
        identifier = userdata['id']
        userlist[identifier] = User(identifier, userdata['pubkey'], userdata['verkey'])
        print "loaded user: %s" % identifier 
        completer.add(identifier)

except Exception, e:
    print "Cannot load `users': %s" % (str(e))
    sys.exit(1)


mqttc = paho.Client('ypom-cli-%s' % os.getpid(), clean_session=True, userdata=None)
mqttc.on_message = on_message
mqttc.on_connect = on_connect
mqttc.on_disconnect = on_disconnect
mqttc.on_publish = on_publish
mqttc.on_subscribe = on_subscribe

mqttc.connect("localhost", 1883, 60)

mqttc.loop_start()

input_loop()

mqttc.loop_stop()
mqttc.disconnect()
