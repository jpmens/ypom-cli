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
    from nacl.public import PrivateKey, PublicKey, Box
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

def topicname(sk32, pk32):
    ''' return an MQTT topic name consisting of a prefix followed
        by the base32-encoded public key of the recipient (TO),
        followed by the base32-encoded public key of the sender (FROM)
        '''
    prefix = 'ypom'

    # to/from
    topic = '%s/%s/%s' % ( prefix, sk32, pk32)
    return topic

class User(object):

    def __init__(self, username, pk64, sk64=None):
        self.username = username
        self.sk = None
        self.sk32 = None
        self.sk64 = None
        self.pk = None
        self.pk32 = None
        self.pk64 = None

        if sk64 is not None:
            self.sk64 = sk64
            self.sk = PrivateKey(sk64, encoder=Base64Encoder)
            self.sk32 = b32encode(self.sk.__bytes__())

        if pk64 is not None:
            self.pk = PublicKey(pk64, encoder=Base64Encoder)
            self.pk32 = b32encode(self.pk.__bytes__())
            self.pk64 = pk64
            b32list[self.pk32] = self

    def send(self, msg, content_type=None):
        ''' Send the clear text 'msg' to this user '''

        box = Box(me.sk, self.pk)

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

        # FIXME: sign!

        out_nonce = encrypted[0:24]
        out_crypted = encrypted[24:]

        nonce =  b64encode(out_nonce)
        ciphertext = b64encode(out_crypted)

        #   to/from
        topic = topicname(self.pk32, me.pk32)
        mqttpayload = '%s:%s' % (nonce, ciphertext)

        mqttc.publish(topic, mqttpayload, qos=2, retain=False)

    def decrypt(self, mqttpayload):

        image_types = {
            'image/png'         : 'png',
            'image/jpeg'        : 'jpg',
            'image/jpg'         : 'jpg',
            'image/gif'         : 'gif',
        }
        box = Box(me.sk, self.pk)
        nonce, encrypted = mqttpayload.split(':')

        nonce = b64decode(nonce)
        ciphertext = b64decode(encrypted)

        plaintext = box.decrypt(ciphertext, nonce=nonce)
        message_data = json.loads(plaintext)

        # print "MSG_DATA = ", message_data
        # {"timestamp":"1394207409.633","_type":"ack"}

        if '_type' in message_data:
            tst = message_data['timestamp']
            time_str = time.strftime('%H:%M', time.localtime(float(tst)))
            if message_data.get('_type') == 'ack':
                return time_str, "ACK"
            if message_data.get('_type') == 'msg':
                message = b64decode(message_data['content'])

                content_type = message_data.get('content-type', 'unknown')
                if content_type in image_types:
                    extension = image_types[content_type]
                    filename = '%s-%s.%s' % (self.username, time.time(), extension)
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

userlist = {}   # indexed by user name
b32list = {}    # indexed by B32 pubkey

def publish_me_pk():
    data = {
        "_type" : "usr",
        "name" : me_data.get('username', 'unknown'),
        "pk" : me_data.get('pk'),
    }
    mqttpayload = json.dumps(data)
    topic = 'ypom/%s' % me.pk32
    mqttc.publish(topic, mqttpayload, qos=2, retain=True)

    topic = 'ypom/%s/users/online' % me.pk32
    mqttc.publish(topic, '1', qos=2, retain=False)


def on_connect(mosq, userdata, rc):
    mqttc.subscribe("ypom/+", 2)
    mqttc.subscribe("ypom/%s/+" % (me.pk32), 2)

def on_message(mosq, userdata, msg):
    # print "%s (qos=%s, r=%s) %s" % (msg.topic, str(msg.qos), msg.retain, str(msg.payload))

    topic = msg.topic
    payload = msg.payload

    if paho.topic_matches_sub('ypom/+', topic):
        try:
            userdata = json.loads(payload)
        except:
            print "Cannot parse JSON"
            return
        if '_type' in userdata and userdata['_type'] == 'usr':
            if 'name' in userdata and 'pk' in userdata:
                username = userdata['name']
                userlist[username] = User(username, userdata['pk'])
                completer.add(username)

    ''' Receive a message.
        ypom/TO/from    (TO == me)
    '''
    if paho.topic_matches_sub('ypom/+/+', topic):
        prefix, to32, from32 = topic.split('/', 3)

        #print "FROM ", from32
        #print "TO   ", to32
        #print "ME pk", me.pk32
        #print "ME sk", me.sk32

        #if str(from32) == str(me.pk32):       # ignore self-sent messages
        #    return

        try:
            u_from = b32list[from32]
            u_to = b32list[to32]

            tst, msg = u_from.decrypt(msg.payload)
            msg = msg.decode('utf-8')
            print u'%s: %s  [%s]' % (u_from.username, msg, tst)
        except:
            raise
            print "SOMETHING WRONG"

def on_publish(mosq, userdata, mid):
    # print("published mid: "+str(mid))
    pass

def on_subscribe(mosq, userdata, mid, granted_qos):
    # print("Subscribed: "+str(mid)+" "+str(granted_qos))
    pass

def on_disconnect(mosq, userdata, rc):
    print "OOOOPS! disconnect"

def quit():
    mqttc.loop_stop()
    mqttc.disconnect()
    sys.exit(0)

def input_loop():
    line = ''
    print "Use TAB-completion for usernames. (quit to exit)"
    while line != 'quit':
        to = message = None
        try:
            line = raw_input("%s> " % me.username)
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
            print "No PK for user %s available" % to
            continue
        u = userlist[to]
        # print u.username, u.pk32,  u.pk64
        # print me.username, me.pk32,  me.pk64

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
    me = User(me_data.get('username', 'ME'), me_data.get('pk'), me_data.get('sk'))
except Exception, e:
    print "Cannot load `me.creds': %s" % (str(e))
    sys.exit(1)


mqttc = paho.Client('ypom-cli-%s' % os.getpid(), clean_session=True, userdata=None)
mqttc.on_message = on_message
mqttc.on_connect = on_connect
mqttc.on_disconnect = on_disconnect
mqttc.on_publish = on_publish
mqttc.on_subscribe = on_subscribe

topic = 'ypom/%s/users/online' % me.pk32
mqttc.will_set(topic, '0', qos=2, retain=False)

mqttc.connect("localhost", 1883, 60)

mqttc.loop_start()

publish_me_pk()

input_loop()

mqttc.loop_stop()
mqttc.disconnect()
