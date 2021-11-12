cryptographic identity toolkit
==============================


a generalization of the devguard sovereign identity managment

implementation:

- [x] golang
- [ ] C
- [ ] rust



## introduction

Privacy and security both start with Identity. Identity is a way to ensure you are in fact you.
While in traditional technical design an identity would be a username and password that is stored by a third party,
devguard uses cryptographic primitives to enable you to give an identity to yourself without registering with anyone.

Identitykit takes the idea further into other use cases, such as email, TLS ("https") or file signatures.


install the identitykit commandline util with go:

```
go install github.com/devguardio/identity/go/ik@latest
```

and initialize your secrets
```
ik init
```
your secrets are stored in ~/.identitykit and you should probably make a backup
do not share those files with anyone. instead share your public identity

```
ik id
```


### file signatures


```
$ echo hello > hello.txt
$ ik m sign hello.txt --detach

$ ik m verify hello.txt.ikdoc hello.txt -i $(ik id)
GOOD

$ echo hellu > hello.txt
$ ik m verify hello.txt.ikdoc hello.txt -i $(ik id)
BAD
```


### sequential anchors and multisig

identitykit generalizes the devguard sequencer into an arbitrary trust anchor.
Signatures carry information about the signee itself in the anchor section.
It can require the next document to be signed by multiple keys, or add and remove authorized keys.
The chain must be strictly sequential and it is NOT safe to use the ik cli concurrently.

```
$ ik sign hello1.txt
$ ik sign hello2.txt --parent hello1.txt.ikdoc
$ ik verify hello1.txt.ikdoc --identity $(ik id)
$ ik verify hello2.txt.ikdoc --parent hello1.txt.ikdoc

```

anchors can require a minimum of members sign a message to be considered signed by the anchor.
in this example, we create two identities and require both

```
$ IDENTITYKIT_PATH=/tmp/Alice   ik init
$ IDENTITYKIT_PATH=/tmp/Bob     ik init
$ IDENTITYKIT_PATH=/tmp/Alice   ik sign hello1.txt --anchor $(IDENTITYKIT_PATH=/tmp/Bob ik id) --quorum 2
$ IDENTITYKIT_PATH=/tmp/Alice   ik sign hello2.txt --precedence hello1.txt.ikdoc

$ ik verify hello1.txt --identity $(IDENTITYKIT_PATH=/tmp/Alice ik id)
GOOD

```

one signature is now insufficient to advance the chain
```

$ ik verify hello2.txt --precedence hello1.txt
insufficient valid signatures

$ IDENTITYKIT_PATH=/tmp/Bob ik sign hello2.txt --precedence hello1.txt
$ ik verify hello2.txt --precedence hello1.txt
GOOD
```


### using identity as x509 CA

it's possible to use identitykit with TLS.
An identity becomes a CA, which can either sign temporary client and server certs or used directly.
Unless you call 'ik pem' , the local secret remains cold.

for example if you want to use cold identity that acts as a "CA" and emits hot server certs:

ik ca > /tmp/ca.pem
ik cert server.domain.com --dns localhost > /tmp/server.pem
openssl s_server -accept 8443 -www -cert /tmp/server.pem
curl  https://localhost:8443   --cacert /tmp/ca.pem

a regular tls client can then verify that the server acts on behalf of the cold identity "ik identity".

You could use export the identity as cert directly.
note that this means the secrets are now in the pem key file, and there's a danger of leaking them.
You probably want to avoid this.

ik tls serve
ik tls ca > /tmp/client.pem
ik tls pem > /tmp/client.key
curl  https://localhost:8443 --cacert /tmp/ca.pem --cert /tmp/client.pem --key /tmp/client.key


"ik tls serve" is an example tls server implemented using

```
tls.Config {
    ClientAuth: tls.RequireAnyClientCert,
    VerifyPeerCertificate: identity.VerifyPeerCertificate,
}
```

which verifies that the peer either has direct posession of the secret key with "ik pem"
or otherwise has a signature chain leading to "ik ca".


### etcd example

for example here's how to setup etcd with a cold CA:

```
ik tls ca > ca.pem
ik tls cert localhost --ip 127.0.0.1 > server.pem
ik tls cert localhost --ip 127.0.0.1 > client.pem
etcd \
    --client-cert-auth=true     \
    --trusted-ca-file ca.pem    \
    --cert-file server.pem      \
    --key-file server.pem       \
    --listen-client-urls='https://localhost:2379' \
    --advertise-client-urls='https://localhost:2379'

etcdctl member list  --cert=client.pem --key=client.pem --cacert=ca.pem
```

