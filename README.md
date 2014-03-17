
## HOWTO
* ./create-ME.py

create-ME creates a keypair for encryption and a second pair for message signing. It hashes and extracts a 8-character base32 identifier from your
public encryption key.

Your secrets are stored in `me.creds`. This data is secret-box-ed. create-ME asks you for a protection phrase. Example:
```
3cdd5670383b14c27079912db601b4d6477e21fb86929e69ec58ba49bfcc48f16a6ce46bca14285b102cdb6ed666463be3f21511762410a50749919242a091a27297eadd7c5cbe305b74adffa581f5b52830550b4721bbe9e8163825e76dba0a3e31f2832b0168d5bcf1f8d69ddc26528cbdd0cb40030283725d05012329616a235382d4f77e2888cb0263c8e1e43843e4217a259cfe5e72bf95f130a23400cb935ce22ee0b3b2a1c527f4394dfb702b37f8d75856a736f100e1685558eb02a5b924c213625dd67509ca93ab2eca457ac42280e6d74cb233f96b9ae45061a989d5a950b851ec2675b502dd880809c405d613b1611f77025f1f0e3685dafd9fd9b9e900573bc6c5b4434161aac104b4dc7a23950e717ca2898e9cc915a196060bc74f
```

Your public address data is stored in `me.ypom`. It contains a cleartext json with your identifier, public encryption key and signing verification key.
You send this file to your communication partners. Example:
```
{"verkey": "Mn9LcroTboiiWKS0Vxn6qL6gV68A3RyfgE7moXzoQpQ=", "pubkey": "9MpEzoCKci0xMFOPKFANX8j67y7gqpTNa5hvQGg6G1s=", "id": "PPD7PXPG"}
```

* ./ypom-cli

ypom-cli prompts you for your protection phrase and loads your secrets from `me.creds`. Example:
```
3cdd5670383b14c27079912db601b4d6477e21fb86929e69ec58ba49bfcc48f16a6ce46bca14285b102cdb6ed666463be3f21511762410a50749919242a091a27297eadd7c5cbe305b74adffa581f5b52830550b4721bbe9e8163825e76dba0a3e31f2832b0168d5bcf1f8d69ddc26528cbdd0cb40030283725d05012329616a235382d4f77e2888cb0263c8e1e43843e4217a259cfe5e72bf95f130a23400cb935ce22ee0b3b2a1c527f4394dfb702b37f8d75856a736f100e1685558eb02a5b924c213625dd67509ca93ab2eca457ac42280e6d74cb233f96b9ae45061a989d5a950b851ec2675b502dd880809c405d613b1611f77025f1f0e3685dafd9fd9b9e900573bc6c5b4434161aac104b4dc7a23950e717ca2898e9cc915a196060bc74f
```
It loads the public address data of your communication partners from the file `users`. Users contains a json string per line,
each containing identifier, public and verification key. Example:
```
{"id":"X6FSDM3S","pubkey":"QqgpYEubdB6NV3qQ0V6aJguOp4telhGfxmzhz+voXCg=","verkey":"jbYnF\/qa+PW90R5P1IfagKRyes1HO5N+fOpNhOW4tcI="}
{"id":"2IPGCPAI","pubkey":"Dz2TUQ0iLzvmVtCUKcpMY4CrJRRfaps8w43JaaDTmjU=","verkey":"3f5O2ZmVWcHZpaOgA4ImE8G+T6gvAHM5HABl2eV5BCw="}
{"id":"4YFMAIL6","verkey":"T\/WO3yhR54UkF2VvrMgMGiT3mr0suzlkROFJu7IVgeU=","pubkey":"ccWSi5JvzCkIAdm2b5qQ9u9DRcl3+4aKfqFwW2\/k4Sw="}
{"id":"X4I5SPSD","pubkey":"N2IPCt+weD8tloV3+6cc8j2oTFM\/DOK0CiNMGZ3K1QM=","verkey":"jg8tdX\/FUkcbJYq8+fcBsH4MG69fHBceYts+itmnyJE="}
{"id":"3NEXHRB4","pubkey":"aG\/+h5Yg2UziNGZD9rBkepaw1YUXWI027tizgBjNKzw=","verkey":"\/f5+1Io8wPcGnSqbMHlyPlSkWDKKIcwx2JVNba5ztmk="}
```
To send a text message type `<identifier>:<message>`. To send an image file type `<identifier>:<<filename>`.

## Features

* credentials data (`me.creds`) encrypted
* content-type recognition
* incoming image files are stored as `<identifier>-<timestamp>.<extension>`
* Upload images to user:
```
identifier: < path.png
```

