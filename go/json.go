package identity;

import (
    "encoding/json"
)

func (b *Identity) MarshalJSON() ([]byte, error) {
    var s = b.String()
    return json.Marshal(&s)
}

func (b *Identity) UnmarshalJSON(data []byte) (err error) {
    var s string

	err = json.Unmarshal(data, &s);
    if err != nil { return }

    v, err := IdentityFromString(s)
    if err != nil { return }

    copy(b[:], v[:])
    return
}



func (b *Signature) MarshalJSON() ([]byte, error) {
    var s = b.String()
    return json.Marshal(&s)
}

func (b *Signature) UnmarshalJSON(data []byte) (err error) {
    var s string

	err = json.Unmarshal(data, &s);
    if err != nil { return }

    v, err := SignatureFromString(s)
    if err != nil { return }

    copy(b[:], v[:])
    return
}



func (b *XPublic) MarshalJSON() ([]byte, error) {
    var s = b.String()
    return json.Marshal(&s)
}

func (b *XPublic) UnmarshalJSON(data []byte) (err error) {
    var s string

	err = json.Unmarshal(data, &s);
    if err != nil { return }

    v, err := XPublicFromString(s)
    if err != nil { return }

    copy(b[:], v[:])
    return
}
