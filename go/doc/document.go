package doc

import (
    "github.com/devguardio/identity/go"
    "fmt"
    "io"
    "encoding/binary"
    "bytes"
    "github.com/fatih/color"
    "crypto/sha256"
    "crypto/subtle"
    "strings"
)


const (
    DocumentFieldEndOfHeader    = 0

    DocumentFieldAttachment     = 1
    DocumentFieldDetachment     = 2
    DocumentFieldAnchor         = 3
    DocumentFieldSequence       = 4

    DocumentFieldSignature      = 9
)

type DocumentSequence struct {
    Serial      identity.Serial
    Precedent   [32]byte
    Lineage     [4]byte
    Quorum      uint16
}

type DocumentDetachment struct {
    Name        string
    Hash        [32]byte
    Size        uint64
}

type DocumentAttachment struct {
    Name        string
    Message     []byte
}

type Document struct {
    Attached        []DocumentAttachment
    Detached        []DocumentDetachment
    Anchors         []identity.Identity
    Sequence        *DocumentSequence

    SignedSize      uint32
    Signatures      []identity.Signature

    DocumentHash    []byte
}

type DocumentOptDump  struct {io.Writer}

func ReadDocument(r io.ReadSeeker, opts ...interface{}) (*Document, error) {

    var debug io.Writer = nil;
    for _,opt := range opts {
        if v, ok := opt.(DocumentOptDump); ok {
            debug = v
        }
    }

    var magic = [4]byte{}
    _, err := io.ReadFull(r, magic[:])
    if err != nil { return nil, err }

    if magic[0] != 'i' || magic[1] != 'k' || magic[2] != 'd' {
        return nil, fmt.Errorf("doesn't look like an ikdoc: invalid magic");
    }
    if debug != nil {
        fmt.Fprintf(debug, "magic:          %s\n", magic);
    }
    if magic[3] != '1' {
        return nil, fmt.Errorf("ik too old to read ikdoc version %c", magic[3]);
    }

    var self = &Document{}
    err = binary.Read(r, binary.LittleEndian, &self.SignedSize);
    if err != nil { return nil, err }

    if debug != nil {
        fmt.Fprintf(debug, "signedsize:     %d\n", self.SignedSize);
    }

    eoh: for ;; {
        var k [1]byte
        _, err := io.ReadFull(r, k[:])
        if err != nil { return nil, fmt.Errorf("reading field type: %w", err) }

        switch k[0] {

        case DocumentFieldAttachment:
            var v = DocumentAttachment{}

            var namelen uint8
            err := binary.Read(r, binary.LittleEndian, &namelen);
            if err != nil { return nil, err }
            var name = make([]byte, namelen)
            _, err = io.ReadFull(r, name[:])
            if err != nil { return nil, err }
            v.Name = string(name)

            var msglen uint32
            err = binary.Read(r, binary.LittleEndian, &msglen);
            if err != nil { return nil, fmt.Errorf("reading content size: %w", err) }
            v.Message = make([]byte, msglen)
            _, err = io.ReadFull(r, v.Message)
            if err != nil { return nil, fmt.Errorf("reading content (%d): %w", msglen, err) }

            if debug != nil {
                fmt.Fprintf(debug, "attached:       %s (%db)\n", v.Name, len(v.Message));
            }
            self.Attached = append(self.Attached, v)

        case DocumentFieldDetachment:
            var v = DocumentDetachment{}

            _, err = io.ReadFull(r, v.Hash[:])
            if err != nil { return nil, fmt.Errorf("reading detach hash field: %w",  err) }
            err := binary.Read(r, binary.LittleEndian, &v.Size);
            if err != nil { return nil, fmt.Errorf("reading detach size field: %w", err) }

            var namelen uint8
            err = binary.Read(r, binary.LittleEndian, &namelen);
            if err != nil { return nil, err }
            var name = make([]byte, namelen)
            _, err = io.ReadFull(r, name[:])
            if err != nil { return nil, err }
            v.Name = string(name)

            if strings.ContainsAny(v.Name, "/") {
                if debug != nil {
                    fmt.Fprintf(debug, "detached:       dropped unsafe key '%s'\n", v.Name);
                }
            } else {
                if debug != nil {
                    fmt.Fprintf(debug, "detached:       %s (%db, %x)\n", v.Name, v.Size, v.Hash);
                }
                self.Detached = append(self.Detached, v)
            }

        case DocumentFieldAnchor:
            var anchor identity.Identity
            _, err = io.ReadFull(r, anchor[:])
            if err != nil { return nil, err }
            self.Anchors = append(self.Anchors, anchor)

            if debug != nil {
                fmt.Fprintf(debug, "anchor:         %s\n", anchor.String());
            }

        case DocumentFieldSequence:
            self.Sequence = &DocumentSequence{}

            err := binary.Read(r, binary.LittleEndian, &self.Sequence.Serial);
            if err != nil { return nil, fmt.Errorf("reading sequence field: %w", err) }

            _, err = io.ReadFull(r, self.Sequence.Precedent[:])
            if err != nil { return nil, fmt.Errorf("reading precedent field: %w",  err) }

            _, err = io.ReadFull(r, self.Sequence.Lineage[:])
            if err != nil { return nil, fmt.Errorf("reading lineage field: %w",  err) }

            err = binary.Read(r, binary.LittleEndian, &self.Sequence.Quorum);
            if err != nil { return nil, fmt.Errorf("reading qourum field: %w", err) }

            if debug != nil {
                fmt.Fprintf(debug, "serial:         %d\n", self.Sequence.Serial);
                fmt.Fprintf(debug, "precedent:      %x\n", self.Sequence.Precedent);
                fmt.Fprintf(debug, "lineage:        %x\n", self.Sequence.Lineage);
                fmt.Fprintf(debug, "quorum:         %d\n", self.Sequence.Quorum);
            }

        case DocumentFieldEndOfHeader:
            break eoh
        default:
            if debug != nil {
                fmt.Fprintf(debug, "unknown field:  %d\n", k[0]);
            }
            break eoh
        }
    }

    _, err = r.Seek(int64(self.SignedSize), 0)
    if err != nil { return nil, fmt.Errorf("seeking to signatures at %d: %w", self.SignedSize, err) }

    eos: for ;; {
        var k [1]byte
        _, err := io.ReadFull(r, k[:])
        if err == io.EOF { break eos }
        if err != nil { return nil, fmt.Errorf("reading unsigned key type: %w", err) }
        switch k[0] {
        case DocumentFieldSignature:

            var v identity.Signature
            _, err = io.ReadFull(r, v[:])
            if err != nil { return nil, fmt.Errorf("reading signatures: %w", err) }
            self.Signatures = append(self.Signatures, v)

            if debug != nil {
                fmt.Fprintf(debug, "signature:      %s\n", v.String());
            }

        default:
            if debug != nil {
                fmt.Fprintf(debug, "unknown field:  %d\n", k[0]);
            }
            break eos
        }
    }

    _, err = r.Seek(0, 0)
    h := sha256.New()
    io.Copy(h, r)
    self.DocumentHash = h.Sum(nil)

    if self.Sequence == nil {
        self.Sequence = &DocumentSequence {
            Serial:     1,
            Quorum:     1,
        }
        copy(self.Sequence.Lineage[:],  self.DocumentHash[:])
    }


    return self, nil
}

func (self *Document) Encode() ([]byte, error) {

    var err error
    var w = bytes.Buffer{}

    w.Write([]byte{'i','k','d','1', 0, 0, 0, 0 })

    for _, t := range self.Attached {
        w.Write([]byte{DocumentFieldAttachment})
        var nameb = []byte(t.Name)
        if len(nameb) > 0xff {
            nameb = nameb[:0xff]
        }
        err = binary.Write(&w, binary.LittleEndian, uint8(len(nameb)))
        if err != nil { return nil, err }
        _, err := w.Write(nameb)
        if err != nil { return nil, err }
        err = binary.Write(&w, binary.LittleEndian, uint32(len(t.Message)))
        if err != nil { return nil, err }
        _, err = w.Write(t.Message)
        if err != nil { return nil, err }
    }
    for _, t := range self.Detached {
        w.Write([]byte{DocumentFieldDetachment})
        _, err = w.Write(t.Hash[:])
        if err != nil { return nil, err }
        err = binary.Write(&w, binary.LittleEndian, t.Size)
        if err != nil { return nil, err }
        var nameb = []byte(t.Name)
        if len(nameb) > 0xff {
            nameb = nameb[:0xff]
        }
        err = binary.Write(&w, binary.LittleEndian, uint8(len(nameb)))
        if err != nil { return nil, err }
        _, err := w.Write(nameb)
        if err != nil { return nil, err }
    }
    for _, t := range self.Anchors {
        if len(t) != 32 { continue }
        w.Write([]byte{DocumentFieldAnchor})
        w.Write(t[:])
    }
    if self.Sequence != nil {
        w.Write([]byte{DocumentFieldSequence})
        err := binary.Write(&w, binary.LittleEndian, uint64(self.Sequence.Serial))
        if err != nil { return nil, err }
        _,err = w.Write(self.Sequence.Precedent[:])
        if err != nil { return nil, err }
        _,err = w.Write(self.Sequence.Lineage[:])
        if err != nil { return nil, err }
        err = binary.Write(&w, binary.LittleEndian, uint32(self.Sequence.Quorum))
        if err != nil { return nil, err }
    }
    w.Write([]byte{DocumentFieldEndOfHeader})

    var b = w.Bytes();
    self.SignedSize = uint32(len(b))
    binary.LittleEndian.PutUint32(b[4:], self.SignedSize)
    return b, nil
}

func (self *Document) EncodeAndSign(s identity.Signer) ([]byte, error) {

    b, err := self.Encode()
    if err != nil { panic(err) }

    sig, err := s.Sign("ikdoc", b[:self.SignedSize])
    if err != nil { panic(err) }

    b = append(b, byte(DocumentFieldSignature))
    b = append(b, sig[:]...)
    return b, nil
}


func (self *Document) Verify() error {

    return nil
}

func (parent *Document) VerifySuccessor(b []byte, opts ...interface{}) (*Document, error) {

    var debug io.Writer = nil;
    for _,opt := range opts {
        if v, ok := opt.(DocumentOptDump); ok {
            debug = v
        }
    }

    evp, err := ReadDocument(bytes.NewReader(b))
    if err != nil { return nil, err }

    err = evp.Verify()
    if err != nil { return nil, err }

    if evp.Sequence == nil {
        return nil, fmt.Errorf("document is not signed in sequence")
    }


    if evp.Sequence.Serial != parent.Sequence.Serial +1 {
        return nil, fmt.Errorf("document is out of order")
    }

    if subtle.ConstantTimeCompare(evp.Sequence.Precedent[:], parent.DocumentHash) != 1 {
        return nil, fmt.Errorf("precedent hash verification failed")
    }

    if debug != nil {
        fmt.Fprintf(debug, "%s %x\n", color.GreenString("✔ parent"), parent.DocumentHash)
    }


    var valid uint16 = 0

    //DO NOT FLIP THE LOOP. otherwise you'd count a dup signature from the same identity twice
    for _, id := range parent.Anchors {
        var match = false
        for _, sig := range evp.Signatures {
            if sig.Verify("ikdoc", b[:evp.SignedSize], &id) {
                match = true
                break;
            }
        }
        if match {
            valid += 1
            if debug != nil {
                fmt.Fprintf(debug, "%s %s\n", color.GreenString("✔ signed"), id.String())
            }
        } else {
            if debug != nil {
                fmt.Fprintf(debug, "%s %s\n", color.RedString  ("✖ nosign"),  id.String())
            }
        }
    }


    if valid < parent.Sequence.Quorum {
        return nil, fmt.Errorf("insufficient valid signatures for a quorum of %d", parent.Sequence.Quorum)
    }
    return evp, nil
}

func (self *Document) WithDetached(f io.Reader, name string) error {
    var v = DocumentDetachment {}

    h := sha256.New()
    h.Write([]byte(name))
    size, err := io.Copy(h, f);
    if err != nil { return err }
    v.Size = uint64(size)

    v.Name = name

    copy(v.Hash[:], h.Sum(nil))
    self.Detached = append(self.Detached, v);
    return nil

}

func (self *Document) WithAttached(b []byte, name string) error {
    self.Attached = append(self.Attached, DocumentAttachment {
        Name:       name,
        Message:    b,
    })
    return nil
}

func (self *Document) NewSequence() *Document {
    var doc  = &Document{}
    doc.Sequence = &DocumentSequence {
        Serial: self.Sequence.Serial + 1,
        Quorum: 1, //TODO we dont copy over the anchors yet
    }
    copy(doc.Sequence.Lineage[:],       self.Sequence.Lineage[:])
    copy(doc.Sequence.Precedent[:],     self.DocumentHash[:])
    return doc
}

