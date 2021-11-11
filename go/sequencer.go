package identity

import (
    "os"
    "fmt"
    "encoding/json"
    "crypto/sha256"
    "path"
    "time"
    "io/ioutil"
    "strings"
    "bytes"
)

type Anchor struct {
    Sequence            Sequence    `json:"sequence"`
    Precedence          string      `json:"precedence,omitempty"`
    Trust               []Identity  `json:"trust"`
    CreatedAt           time.Time   `json:"created_at"`
    SignatureQuorum     uint        `json:"signature_quorum"`
    AdvanceQuorum       uint        `json:"advance_quorum"`

    Digest              string      `json:"-"`
}

func NewAnchor(vault VaultI, name string, first *Identity) error {

    var p = path.Join(DefaultPath(), "anchors" , name)

    if _, err := os.Stat(p); err == nil {
        return fmt.Errorf("%s already exists", p);
    }

    err := os.MkdirAll(path.Join(p, "heads"), os.ModePerm)
    if err != nil { return err }

    err = os.MkdirAll(path.Join(p, "sha256"), os.ModePerm)
    if err != nil { return err }

    js, err := json.Marshal(&Anchor{
        Sequence:           1,
        Trust:              []Identity{*first},
        CreatedAt:          time.Now(),
        SignatureQuorum:    1,
        AdvanceQuorum:      1,
    })
    if err != nil { return err }

    h := sha256.New()
	h.Write(js)

    sum := fmt.Sprintf("%x", h.Sum(nil))

    pf := path.Join(p, "sha256", sum)

    err = os.WriteFile(pf, js, 0644)
    if err != nil { return err }

    sig, err := vault.Sign ("iksig", js)
    if err != nil { return err }

    err = os.WriteFile(pf + ".iksig", []byte(sig.String() + "\n"), 0644)
    if err != nil { return err }

    err = os.WriteFile(path.Join(p, "heads", "anchor"), []byte("sha256/" + sum + "\n"), 0644)
    if err != nil { return err }

    return nil
}

func LoadAnchor(vault VaultI, name string) (*Anchor, error) {

    var p = path.Join(DefaultPath(), "anchors", name)

    var pf = path.Join(p, "heads", "anchor")

    b, err := ioutil.ReadFile(pf)
    if err != nil { return nil, fmt.Errorf("%s : %w", pf, err) }
    sum := strings.TrimSpace(string(b))

    pf = path.Join(p, sum)

    js, err := ioutil.ReadFile(pf)
    if err != nil { return nil, fmt.Errorf("%s : %w", pf, err) }

    var anchor = &Anchor{}
	err = json.Unmarshal(js, anchor);
    if err != nil { return nil, fmt.Errorf("%s : %w", pf, err) }

    anchor.Digest = sum

    return anchor, nil
}

func (self *Anchor) Verify(advance bool, subject string, message []byte, signatures []Signature) error {

    var valid uint = 0

    //DO NOT FLIP THE LOOP. otherwise you'd count a dup signature from the same identity twice
    for _, id := range self.Trust {
        for _, sig := range signatures {
            if sig.Verify(subject, message, &id) {
                valid += 1
                fmt.Println("valid signature by " + id.String())
                break;
            }
        }
    }

    if advance {
        if self.AdvanceQuorum == 0 {
            return fmt.Errorf("invalid advance_quorum: 0")
        }
        if valid <  self.AdvanceQuorum  {
            return fmt.Errorf("insufficient valid signatures")
        }
    } else {
        if self.SignatureQuorum == 0 {
            return fmt.Errorf("invalid signature_quorum: 0")
        }
        if valid <  self.SignatureQuorum  {
            return fmt.Errorf("insufficient valid signatures")
        }
    }
    return nil
}


func AppendRemoveAnchor(vault VaultI, name string, nuid *Identity, remove bool, advanceQuorum, signatureQuorum uint) (*Anchor, error) {

    var p = path.Join(DefaultPath(), "anchors" , name)

    head, err := LoadAnchor(vault , name )
    if err != nil { return nil, err }

    var found = false
    for _, t := range head.Trust {
        if bytes.Equal(t[:], nuid[:]) {
            found = true
            break
        }
    }

    if remove && !found{
        return nil, fmt.Errorf("identity not a member");
    } else if !remove && found {
        return nil, fmt.Errorf("identity already a member");
    }

    nu := &Anchor{
        Sequence:           head.Sequence + 1,
        Precedence:         head.Digest,
        CreatedAt:          time.Now(),
        SignatureQuorum:    head.SignatureQuorum,
        AdvanceQuorum:      head.AdvanceQuorum,
    }

    if remove {
        nu.Trust = make([]Identity, 0)
        for _, t := range head.Trust {
            if bytes.Equal(t[:], nuid[:]) {
                continue
            }
            nu.Trust = append(nu.Trust, t)
        }
    } else {
        nu.Trust = append(head.Trust, *nuid)
    }

    if advanceQuorum > 0 {
        nu.AdvanceQuorum = advanceQuorum
    }
    if signatureQuorum > 0 {
        nu.SignatureQuorum = signatureQuorum
    }
    if int(nu.AdvanceQuorum) > 1  {
        return nil, fmt.Errorf("advance quorum > 1 not yet supported")
    }

    if int(nu.AdvanceQuorum) > 1 && int(nu.AdvanceQuorum) >= len(nu.Trust) {
        return nil, fmt.Errorf("invalid advance quorum: %d/%d. must hold quorum < members", nu.AdvanceQuorum,len(nu.Trust))
    }
    if int(nu.SignatureQuorum) > 1 && int(nu.SignatureQuorum) > len(nu.Trust) {
        return nil, fmt.Errorf("invalid signature quorum: %d/%d. must hold quorum <= members", nu.SignatureQuorum,len(nu.Trust))
    }

    js , err := json.Marshal(&nu);
    if err != nil { return nil, err }

    h := sha256.New()
	h.Write(js)

    sum := fmt.Sprintf("%x", h.Sum(nil))

    nu.Digest = "sha256/" + sum

    pf := path.Join(p, nu.Digest)

    err = os.WriteFile(pf, js, 0644)
    if err != nil { return nil, err }

    sig, err := vault.Sign ("iksig", js)
    if err != nil { return nil, err }

    err = os.WriteFile(pf + ".iksig", []byte(sig.String() + "\n"), 0644)
    if err != nil { return nil, err }

    err = os.WriteFile(path.Join(p, "heads", "anchor"), []byte(nu.Digest + "\n"), 0644)
    if err != nil { return nil, err }

    return nu, nil
}
