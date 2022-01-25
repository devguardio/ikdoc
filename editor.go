package ikdoc


import (
    "fmt"
    ik "github.com/devguardio/identity/go"
    "crypto/rand"
)

type Editor struct {

    parent      *Document
    doc         *Document

    sealkey     *ik.Secret
    ratchet     *ik.Secret

    opReset     bool
    opYeet      map[string]bool
}

func Create() (*Editor, error) {

    var self = &Editor{}
    var err error

    self.doc = &Document {}

    var chainkey ik.Secret
    _, err = rand.Read(chainkey[:])
    if err != nil { return nil, err }

    sealkey, _ , ratchetkey := Ratchet([]byte{}, chainkey[:])
    self.sealkey = &sealkey
    self.ratchet = &ratchetkey

    return self, nil

}

func Edit(docbytes, secretbytes []byte) (*Editor, error) {

    var self = &Editor{}
    var err error

    if secretbytes != nil {
        sealkey, chainkey, err := ResumeRatchetFromString(string(secretbytes))
        if err != nil { return nil, fmt.Errorf("iksecret : %w", err) }

        self.parent, err = ParseDocument(docbytes, OptUnsealKey(sealkey))
        if err != nil { return nil, err }

        sealkey, _ , ratchetkey := Ratchet(docbytes, chainkey[:])
        self.sealkey = &sealkey
        self.ratchet = &ratchetkey

    } else {
        self.parent, err = ParseDocument(docbytes)
        if err != nil { return nil, err }
    }

    self.doc = self.parent.NewSequence();

    if self.parent.Sealed != nil {
        self.makeSealed()
        for _,v := range self.parent.Sealed.Attached {
            err = self.doc.Sealed.WithAttached(v.Message, v.Name)
            if err != nil { return self, err }
        }
    }

    for _,v := range self.parent.Attached {
        err = self.doc.WithAttached(v.Message, v.Name)
        if err != nil { panic(err) }
    }


    return self, nil
}


// remove all values
func (self *Editor) Clear() error {
    self.doc.Attached = nil
    self.doc.Detached = nil
    self.doc.Sealed   = nil
    return nil
}

// remove all values with this key
func (self *Editor) Remove(key string) error {

    var attached []DocumentAttachment
    for _,v := range self.doc.Attached {
        if v.Name == key { continue }
        attached = append(attached, v)
    }
    self.doc.Attached = attached

    var detached []DocumentDetachment
    for _,v := range self.doc.Detached{
        if v.Name == key { continue }
        detached = append(detached, v)
    }
    self.doc.Detached = detached

    if self.doc.Sealed != nil {
        var attached []DocumentAttachment
        for _,v := range self.doc.Sealed.Attached {
            if v.Name == key { continue }
            attached = append(attached, v)
        }
        self.doc.Sealed.Attached = attached

        var detached []DocumentDetachment
        for _,v := range self.doc.Sealed.Detached{
            if v.Name == key { continue }
            detached = append(detached, v)
        }
        self.doc.Sealed.Detached = detached
    }

    // yeet empty sealed doc
    if self.doc.Sealed != nil && len(self.doc.Sealed.Attached) == 0 && len(self.doc.Sealed.Detached) == 0 {
        self.doc.Sealed = nil
    }

    return nil
}

func (self *Editor) AppendPlaintextMessage(k string, v []byte) error {
    return self.doc.WithAttached(v, k)
}

func (self *Editor) AppendSealedMessage(k string, v []byte) error {
    err := self.makeSealed()
    if err != nil { return err }

    return self.doc.Sealed.WithAttached(v, k)
}


func (self *Editor) Edit(key string, f func([]byte) ([]byte, error)) error {

    var err error

    var attached []DocumentAttachment
    for _,v := range self.doc.Attached {
        if v.Name == key {
            v.Message, err = f(v.Message)
            if err != nil { return err }
        }
        attached = append(attached, v)
    }
    self.doc.Attached = attached

    if self.doc.Sealed != nil {
        var attached []DocumentAttachment
        for _,v := range self.doc.Sealed.Attached {
            if v.Name == key {
                v.Message, err = f(v.Message)
                if err != nil { return err }
            }
            attached = append(attached, v)
        }
        self.doc.Sealed.Attached = attached
    }

    return nil
}

func (self *Editor) makeSealed() error {

    if self.doc.Sealed != nil { return nil }

    self.doc.Sealed = NewSealedDocument(self.sealkey[:])

    if self.parent == nil {
        self.doc.Sealed.Salt = make([]byte, 8)
        _, err := rand.Read(self.doc.Sealed.Salt)
        if err != nil { return err }
    }

    return nil
}

func (self *Editor) EncodeAndSign(s ik.Signer) (document []byte, secret *ik.Secret, err error) {
    doc, err := self.doc.EncodeAndSign(s)
    return doc, self.ratchet, err
}



