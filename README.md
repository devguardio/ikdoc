cryptographic identity toolkit
==============================


a generalization of the devguard sovereign identity managment

implementation:

- [x] golang
- [ ] C
- [ ] rust




### file signatures


```
$ echo hello > hello.txt
$ ikdoc sign hello.ikdoc hello.txt

$ ikdoc verify hello.ikdoc -i $(ik id)
GOOD

$ echo hellu > hello.txt
$ ikdoc verify hello.ikdoc -i $(ik id) 
BAD
```


### sequential anchors with multisig

identitykit generalizes the devguard sequencer into an arbitrary trust anchor.
Signatures carry information about the signee itself in the anchor section.
It can require the next document to be signed by multiple keys, or add and remove authorized keys.
The chain must be strictly sequential and it is NOT safe to use the ik cli concurrently.

```
$ ikdoc sign genesis.ikdoc
$ ikdoc sign hello.ikdoc hello.txt --parent genesis.ikdoc
$ ikdoc verify genesis.ikdoc --identity $(ik id)
$ ikdoc verify hello.ikdoc --parent genesis.ikdoc
```

### encryption ratchet

the chain can be used as an HKDF ratchet. A document can only be read
if the recipient can obtain _all_  previous messages without missing any.
Obtaining an older message does not reveal the key of future messages.
Ideally you would treat the genesis document like a preshared secret,
and distribute future documents through multiple channels.

```
$ ikdoc sign genesis.ikdoc
$ ikdoc sign hello.ikdoc -m hello=world --parent genesis.ikdoc

$ ikdoc verify genesis.ikdoc --identity $(ik id)
$ ikdoc verify hello.ikdoc --parent genesis.ikdoc
```



### ikdoc layout

- foo.ikdoc         the document
- foo.iksecret      the current ratchet prk
- .ikchain          previous documents
    - (sha)         previous document
    - (sha).next    sha of the follow up document



