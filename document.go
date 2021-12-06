package ikdoc

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
    "path/filepath"
    "os"
    "bufio"
)


const (
    DocumentFieldEndOfHeader    = iota

    DocumentFieldSerial
    DocumentFieldAnchor
    DocumentFieldPrecedent256
    DocumentFieldQuorum
    DocumentFieldSalt
    DocumentFieldAttachment
    DocumentFieldDetachment
    DocumentFieldBaseUrl
    DocumentFieldSealed

    DocumentFieldSignature
)


type DocumentDetachment struct {
    Name            string
    Size            uint64
    Hash            [32]byte
}

type DocumentAttachment struct {
    Name        string
    Message     []byte
}

type Document struct {
    Attached        []DocumentAttachment
    Detached        []DocumentDetachment
    Anchors         []identity.Identity

    Sealed*         Document

    Serial          identity.Serial
    Precedent       []byte
    Quorum          uint16

    BaseUrl         []string
    Salt            []byte

    SignedSize      uint32
    Signatures      []identity.Signature

    DocumentHash    []byte
    key             []byte
}

type OptDump        struct {io.Writer}
type OptDumpPrintf  func(w io.Writer, format string, a ...interface{}) (int, error)
type OptUnsealKey   identity.Secret

func (self *Document) decodeContent(rr []byte, opts ... interface{}) error {

    var unsealkey *identity.Secret
    var debug  io.Writer = nil;
    var fprintf = fmt.Fprintf
    for _,opt := range opts {
        if v, ok := opt.(OptDump); ok {
            debug = v
        }
        if v, ok := opt.(OptDumpPrintf); ok {
            fprintf = v
        }
        if v, ok := opt.(OptUnsealKey); ok {
            unsealkey = (*identity.Secret)(&v)
        }
    }

    r := bufio.NewReader(bytes.NewReader(rr))
    for ;; {
        k, err := r.ReadByte()
        if err != nil {
            if err == io.EOF {
                return nil
            }
            return fmt.Errorf("reading field type: %w", err)
        }

        switch k {

        case DocumentFieldAttachment:
            var v = DocumentAttachment{}

            nlen, err := binary.ReadUvarint(r)
            if err != nil { return err }
            if nlen > uint64(len(rr)) {
                return fmt.Errorf("implausible field size: %d",  nlen)
            }
            var name = make([]byte, nlen)
            _, err = io.ReadFull(r, name[:])
            if err != nil { return err }
            v.Name = string(name)

            msglen, err := binary.ReadUvarint(r)
            if err != nil { return fmt.Errorf("reading content size: %w", err) }
            if msglen > uint64(len(rr)) {
                return fmt.Errorf("implausible field size: %d",  msglen)
            }
            v.Message = make([]byte, msglen)
            _, err = io.ReadFull(r, v.Message)
            if err != nil { return fmt.Errorf("reading content (%d): %w", msglen, err) }

            if debug != nil {
                fprintf(debug, "attached:       %s (%db)\n", v.Name, len(v.Message));
            }
            self.Attached = append(self.Attached, v)

        case DocumentFieldDetachment:
            var v = DocumentDetachment{}

            nlen, err := binary.ReadUvarint(r)
            if err != nil { return err }
            if nlen > uint64(len(rr)) {
                return fmt.Errorf("implausible field size: %d",  nlen)
            }
            var name = make([]byte, nlen)
            _, err = io.ReadFull(r, name[:])
            if err != nil { return err }
            v.Name = string(name)

            v.Size, err = binary.ReadUvarint(r)
            if err != nil { return fmt.Errorf("reading detach size field: %w", err) }

            _, err = io.ReadFull(r, v.Hash[:])
            if err != nil { return fmt.Errorf("reading detach hash field: %w",  err) }

            if debug != nil {
                if v.Name == "" {
                    fprintf(debug, "detached:       %x %db\n",    v.Hash, v.Size);
                } else {
                    fprintf(debug, "detached:       %x %db \"%s\"\n", v.Hash, v.Size, v.Name);
                }
            }
            self.Detached = append(self.Detached, v)

        case DocumentFieldAnchor:
            var anchor identity.Identity
            _, err = io.ReadFull(r, anchor[:])
            if err != nil { return err }
            self.Anchors = append(self.Anchors, anchor)

            if debug != nil {
                fprintf(debug, "anchor:         %s\n", anchor.String());
            }

        case DocumentFieldSerial:
            serial, err := binary.ReadUvarint(r)
            if err != nil { return fmt.Errorf("reading sequence field: %w", err) }
            self.Serial = identity.Serial(serial)

            if debug != nil {
                fprintf(debug, "serial:         %d\n", self.Serial);
            }

        case DocumentFieldPrecedent256:

            self.Precedent = make([]byte , 32)
            _, err = io.ReadFull(r, self.Precedent[:])
            if err != nil { return fmt.Errorf("reading precedent field: %w",  err) }

            if debug != nil {
                fprintf(debug, "precedent:      %x\n", self.Precedent);
            }

        case DocumentFieldQuorum:

            quorum , err := binary.ReadUvarint(r)
            if err != nil { return fmt.Errorf("reading quorum field: %w", err) }
            self.Quorum = uint16(quorum)

            if debug != nil {
                fprintf(debug, "quorum:         %d\n", self.Quorum);
            }

        case DocumentFieldBaseUrl:
            nlen, err := binary.ReadUvarint(r)
            if err != nil { return fmt.Errorf("reading base url size: %w",  err) }
            if nlen > uint64(len(rr)) {
                return fmt.Errorf("implausible field size: %d",  nlen)
            }

            var vb = make([]byte, nlen)
            _, err = io.ReadFull(r, vb)
            if err != nil { return fmt.Errorf("reading url field: %w",  err) }

            self.BaseUrl = append(self.BaseUrl, string(vb))

            if debug != nil {
                fprintf(debug, "base url:       %s\n", string(vb));
            }

        case DocumentFieldSalt:
            nlen, err := binary.ReadUvarint(r)
            if err != nil { return fmt.Errorf("reading sealkey size: %w",  err) }
            if nlen > uint64(len(rr)) {
                return fmt.Errorf("implausible field size: %d",  nlen)
            }

            var vb = make([]byte, nlen)
            _, err = io.ReadFull(r, vb)
            if err != nil { return fmt.Errorf("  reading salt field: %w",  err) }

            self.Salt = append(self.Salt)

            if debug != nil {
                fprintf(debug, "salt:           %x\n", vb);
            }

        case DocumentFieldSealed:
            nlen, err := binary.ReadUvarint(r)
            if err != nil { return fmt.Errorf("reading sealed size: %w",  err) }
            if nlen > uint64(len(rr)) {
                return fmt.Errorf("implausible field size: %d",  nlen)
            }

            if debug != nil {
                fprintf(debug, "sealed:         %db\n", nlen);
            }

            var vb = make([]byte, nlen)
            _, err = io.ReadFull(r, vb)
            if err != nil { return fmt.Errorf("reading sealed field: %w",  err) }

            if unsealkey != nil {

                vb, err = Unseal(unsealkey[:], uint64(self.Serial), vb)
                if err != nil { return err }

                err = self.decodeContent(vb, append(opts, OptDumpPrintf(
                    func (w io.Writer, format string, a ...interface{}) (int, error) {
                        fprintf(w, "  sealed " + format, a...);
                        return 0, nil
                    },
                ))...);
                if err != nil { return err }

            }

        default:
            if debug != nil {
                fprintf(debug, "unknown field:  %d\n", k);
            }
            return nil
        }
    }
}

func ParseDocument(rr []byte, opts ...interface{}) (*Document, error) {

    var err error

    var debug io.Writer = nil;
    for _,opt := range opts {
        if v, ok := opt.(OptDump); ok {
            debug = v
        }
    }

    if len(rr) < 6 || rr[0] != 'i' {
        return nil, fmt.Errorf("doesn't look like an ikdoc: invalid magic");
    }
    if rr[1] != '1' {
        return nil, fmt.Errorf("ik too old to read ikdoc version %c", rr[1]);
    }

    if debug != nil {
        fmt.Fprintf(debug, "magic:            %s\n", rr[0:2]);
    }


    var self = &Document{}
    self.SignedSize = binary.LittleEndian.Uint32(rr[2:6])

    if debug != nil {
        fmt.Fprintf(debug, "signed content:   %db\n", self.SignedSize);
    }

    err = self.decodeContent(rr[6:self.SignedSize], append(opts, OptDumpPrintf(
        func (w io.Writer, format string, a ...interface{}) (int, error) {
            return fmt.Fprintf(w, "  " + format, a...);
        },
    ))...);
    if err != nil { return nil, err }


    r2 := bytes.NewReader(rr)
    _, err = r2.Seek(int64(self.SignedSize), 0)
    if err != nil { return nil, fmt.Errorf("seeking to signatures at %d: %w", self.SignedSize, err) }

    eos: for ;; {
        var k [1]byte
        _, err := io.ReadFull(r2, k[:])
        if err == io.EOF { break eos }
        if err != nil { return nil, fmt.Errorf("reading unsigned key type: %w", err) }
        switch k[0] {
        case DocumentFieldSignature:

            var v identity.Signature
            _, err = io.ReadFull(r2, v[:])
            if err != nil { return nil, fmt.Errorf("reading signatures: %w", err) }
            self.Signatures = append(self.Signatures, v)

            if debug != nil {
                fmt.Fprintf(debug, "signature:        %s\n", v.String());
            }

        default:
            if debug != nil {
                fmt.Fprintf(debug, "unknown ufield: %d\n", k[0]);
            }
            break eos
        }
    }

    _, err = r2.Seek(0, 0)
    h := sha256.New()
    io.Copy(h, r2)
    self.DocumentHash = h.Sum(nil)

    if self.Serial == 0 {
        self.Serial = 1
    }
    if self.Quorum == 0 {
        self.Quorum = 1
    }

    return self, nil
}

func (self *Document) encodeContent(w io.Writer) (error) {
    var err error
    var uvbuf [binary.MaxVarintLen64]byte

    if self.Serial > 1 {
        w.Write([]byte{DocumentFieldSerial})

        n := binary.PutUvarint(uvbuf[:], uint64(self.Serial))
        _, err = w.Write(uvbuf[:n])
        if err != nil { return err }
    }
    for _, t := range self.Anchors {
        if len(t) != 32 { continue }
        w.Write([]byte{DocumentFieldAnchor})
        w.Write(t[:])
    }

    if len(self.Precedent) == 32 {

        w.Write([]byte{DocumentFieldPrecedent256})
        _,err = w.Write(self.Precedent[:])
        if err != nil { return err }

    }

    if self.Quorum > 1 {
        w.Write([]byte{DocumentFieldQuorum})
        n := binary.PutUvarint(uvbuf[:], uint64(self.Quorum))
        _, err = w.Write(uvbuf[:n])
        if err != nil { return err }
    }

    if len(self.Salt) > 0 {

        w.Write([]byte{DocumentFieldSalt})

        n := binary.PutUvarint(uvbuf[:], uint64(len(self.Salt)))
        _, err = w.Write(uvbuf[:n])
        if err != nil { return err }

        w.Write(self.Salt[:])
    }

    for _, t := range self.BaseUrl {
        w.Write([]byte{DocumentFieldBaseUrl})

        var vb = []byte(t)

        n := binary.PutUvarint(uvbuf[:], uint64(len(vb)))
        _, err = w.Write(uvbuf[:n])
        if err != nil { return err }

        w.Write(vb[:])
    }

    for _, t := range self.Attached {
        w.Write([]byte{DocumentFieldAttachment})

        var nameb = []byte(t.Name)
        n := binary.PutUvarint(uvbuf[:], uint64(len(nameb)))
        _, err = w.Write(uvbuf[:n])
        if err != nil { return err }
        _, err = w.Write(nameb)
        if err != nil { return err }

        n = binary.PutUvarint(uvbuf[:], uint64(len(t.Message)))
        _, err = w.Write(uvbuf[:n])
        if err != nil { return err }
        _, err = w.Write(t.Message)
        if err != nil { return err }
    }
    for _, t := range self.Detached {
        w.Write([]byte{DocumentFieldDetachment})

        var nameb = []byte(t.Name)
        n := binary.PutUvarint(uvbuf[:], uint64(len(nameb)))
        _, err = w.Write(uvbuf[:n])
        if err != nil { return err }
        _, err = w.Write(nameb)
        if err != nil { return err }

        n = binary.PutUvarint(uvbuf[:], uint64(t.Size))
        _, err = w.Write(uvbuf[:n])
        if err != nil { return err }

        _, err = w.Write(t.Hash[:])
        if err != nil { return err }
    }

    if self.Sealed != nil {
        w.Write([]byte{DocumentFieldSealed})
        if len(self.Sealed.key) != 32 {
            return fmt.Errorf("invalid seal key length: %d", self.Sealed.key);
        }

        var w2 = bytes.Buffer{}
        err = self.Sealed.encodeContent(&w2)
        if err != nil { return err }
        var vb = w2.Bytes()

        vb, err = Seal(self.Sealed.key, uint64(self.Serial), vb)
        if err != nil { return err }

        n := binary.PutUvarint(uvbuf[:], uint64(len(vb)))
        _, err = w.Write(uvbuf[:n])
        if err != nil { return err }

        w.Write(vb[:])

    }

    return nil
}

func (self *Document) Encode() ([]byte, error) {

    var w = bytes.Buffer{}
    w.Write([]byte{'i','1', 0, 0, 0, 0 })

    err := self.encodeContent(&w)
    if err != nil { return nil, err }

    var b = w.Bytes();
    self.SignedSize = uint32(len(b))
    binary.LittleEndian.PutUint32(b[2:], self.SignedSize)

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
        if v, ok := opt.(OptDump); ok {
            debug = v
        }
    }

    evp, err := ParseDocument(b)
    if err != nil { return nil, err }

    err = evp.Verify()
    if err != nil { return nil, err }

    if evp.Serial != parent.Serial +1 {
        return nil, fmt.Errorf("document is out of order")
    }

    if subtle.ConstantTimeCompare(evp.Precedent[:], parent.DocumentHash) != 1 {
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


    if valid < parent.Quorum {
        return nil, fmt.Errorf("insufficient valid signatures for a quorum of %d", parent.Quorum)
    }
    return evp, nil
}

func (self *Document) WithDetached(f io.Reader, name string) error {
    var v = DocumentDetachment {}

    h := sha256.New()
    size, err := io.Copy(h, f);
    if err != nil { return err }
    v.Size = uint64(size)

    v.Name = name

    copy(v.Hash[:], h.Sum(nil))
    self.Detached = append(self.Detached, v);
    return nil

}

func (self *Document) WithAttached(b []byte, name string) error {
    self.Attached= append(self.Attached, DocumentAttachment {
        Name:       name,
        Message:    b,
    })
    return nil
}

func (self *Document) WithBaseUrl(url string) error {
    self.BaseUrl = append(self.BaseUrl, url)
    return nil
}

func (self *Document) NewSequence() *Document {
    var doc  = &Document{}
    doc.Serial = self.Serial + 1
    //TODO we dont copy over the anchors and quorum yet
    doc.Precedent = make([]byte, len(self.DocumentHash))
    copy(doc.Precedent[:],  self.DocumentHash[:])
    return doc
}

func NewSealedDocument(k []byte) *Document {
    return &Document{
        key: k,
    }
}


func (doc *Document) VerifyDetached(searchdir string, ignoremissing bool, opts ...interface{}) error {

    var debug io.Writer = nil;
    for _,opt := range opts {
        if v, ok := opt.(OptDump); ok {
            debug = v
        }
    }

    var failed = false
    for _,v := range doc.Detached {
        if strings.Contains(v.Name, "/") {
            return fmt.Errorf("illegal name %s", v.Name)
        }
        rel := filepath.Join(searchdir, v.Name)

        f, err := os.Open(rel)
        if err != nil {
            if debug != nil {
                fmt.Fprintf(debug, "%s %s : %s\n", color.RedString("✖ detach"), v.Name, err);
            }
            if !ignoremissing {
                failed = true
            }
            continue
        }
        defer f.Close();

        h := sha256.New()
        size, err := io.Copy(h, f);
        if err != nil { return fmt.Errorf("%s : %w", rel, err) }

        if subtle.ConstantTimeCompare(v.Hash[:], h.Sum(nil)) != 1 {
            if debug != nil {
                fmt.Fprintf(debug, "%s %s : hash verification failed\n", color.RedString("✖ detach"), rel)
            }
            failed = true
            continue
        }

        if v.Size != uint64(size) {
            return fmt.Errorf("%s : file size is different. did you hit the hash collision jackpot?", rel)
        }

        fmt.Println(color.GreenString("✔ detach"), v.Name)
    }

    if failed {
        return fmt.Errorf("detached content verification failed")
    } else {
        return nil
    }
}
