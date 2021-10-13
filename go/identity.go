package identity

import (
    "crypto/rand"
    "crypto"
    "encoding/base32"
    "github.com/shengdoushi/base58"
    "github.com/go-daq/crc8"
    "bytes"
    "errors"
    "strings"
    "strconv"
    "golang.org/x/crypto/curve25519"
    "golang.org/x/crypto/ed25519"
    "crypto/rsa"
    "crypto/x509"
    "encoding/binary"

    x25519   "github.com/oasisprotocol/curve25519-voi/primitives/x25519"
	ed25519_ "github.com/oasisprotocol/curve25519-voi/primitives/ed25519"

    "fmt"
)

// type 2^4 = max 15.
type SecretKit  struct {Identity  Secret;  Network Secret;}; // type 1

type Secret     [32]byte; // type 3
type XSecret    [32]byte; // type 4
type RSASecret  rsa.PrivateKey;   // type 5

type XPublic    [32]byte; // type 6
type RSAPublic  rsa.PublicKey;   // type 8
type Identity   [32]byte; // type 9

type Signature  [64]byte; // type 10
type Sequence   uint64;   // type 11
type Message    struct {Key string; Value []byte }  // type 14
// type 15 reserved for extended type

// -- secret

func CreateSecret() (*Secret, error) {
    var secret = Secret{};
    _, err := rand.Read(secret[:])
    return &secret, err;
}

// no implicit conversion for safety
func (self *Secret) String() string  {
    return "<secret redacted>"
}

func (self *Secret) ToString() string  {
    return to_str(3, self[:]);
}

func (self *Secret) Identity() *Identity {
    return IdentityFromSecret(self)
}

func (self *Secret) Xor(otp * Secret) Secret{
    var r Secret;
    for i :=0;i<32;i++ {
        r[i] = self[i] ^ otp[i]
    }
    return r;
}

func (self *Secret) Clear() {
    for i := 0; i<32; i++ {
        self[i] = 0;
    }
}

func (self *Secret) XSecret() *XSecret{
    var b = x25519.EdPrivateKeyToX25519(ed25519_.PrivateKey(self[:]))
    var r XSecret;
    copy(r[:], b[:])
    return &r
}


func SecretFromString(from string) (*Secret, error) {
    a, err := from_str(from, 3, 32)
    if err != nil {
        return nil, err;
    }
    if len(a) < 32 {
        return nil, fmt.Errorf("expected 32 bytes, got %d", len(a));
    }

    var r Secret;
    copy(r[:], a[:])
    return &r, nil;
}


// -- xsecret

func CreateXSecret() (*Secret, error) {
    var secret = Secret{};
    _, err := rand.Read(secret[:])
    return &secret, err;
}

// no implicit conversion for safety
func (self *XSecret) String() string  {
    return "<secret redacted>"
}

func (self *XSecret) ToString() string  {
    return to_str(4, self[:]);
}

func XSecretFromString(from string) (*XSecret, error) {
    a, err := from_str(from, 4, 32)
    if err != nil {
        return nil, err;
    }
    if len(a) < 32 {
        return nil, fmt.Errorf("expected 32 bytes");
    }

    var r XSecret;
    copy(r[:], a[:])
    return &r, nil;
}

func (self *XSecret) XPublic() *XPublic {
    return XPublicFromSecret(self)
}

func (self *XSecret) X25519(pub *XPublic) *Secret {

    var r Secret;
    curve25519.ScalarMult((*[32]byte)(&r), (*[32]byte)(self), (*[32]byte)(pub));

    var err = nullcheck(r[:]);
    if err != nil {
        return nil
    }
    return &r;
}

// -- rsasecret

func CreateRSASecret(size int) (*RSASecret, error) {
    k, err := rsa.GenerateKey(rand.Reader, size)
    return (*RSASecret)(k), err;
}

// no implicit conversion for safety
func (self *RSASecret) String() string  {
    return "<secret redacted>"
}

func (self *RSASecret) ToString() string  {
    var b = x509.MarshalPKCS1PrivateKey((*rsa.PrivateKey)(self))
    return to_str(5, b[:]);
}

func RSASecretFromString(from string) (*RSASecret, error) {
    a, err := from_str(from, 5, 0)
    if err != nil {
        return nil, err;
    }

    k, err := x509.ParsePKCS1PrivateKey(a)
    if err != nil {
        return nil, err;
    }
    return (*RSASecret)(k), nil
}

func (self *RSASecret) RSAPublic() *RSAPublic {
    return (*RSAPublic)(((*rsa.PrivateKey)(self)).Public().(*rsa.PublicKey))
}

// -- rsapublic

// no implicit conversion for safety
func (self *RSAPublic) String() string  {
    return self.ToString()
}

func (self *RSAPublic) ToString() string  {
    var b = x509.MarshalPKCS1PublicKey((*rsa.PublicKey)(self))
    return to_str(5, b[:]);
}

// -- signature

func (self *Signature) String() string {
    return to_str(10, self[:]);
}

func SignatureFromString(from string) (*Signature, error) {
    a, err := from_str(from, 10, 64)
    if err != nil {
        return nil, err;
    }
    if len(a) < 64 {
        return nil, fmt.Errorf("expected 64 bytes");
    }

    var r Signature;
    copy(r[:], a[:])
    return &r, nil;
}

func (self *Signature) Verify(subject string, message []byte, signer *Identity) bool {
    return ed25519.Verify(
        ed25519.PublicKey(signer[:]),
        append([]byte(subject), message...),
        self[:],
    )

}

func (self *Secret) Sign(subject string, message []byte) (*Signature, error) {
    var err = nullcheck(self[:]);
    if err != nil {
        return nil, err
    }
    if len(subject) == 0 {
        return nil, fmt.Errorf("signature subject cannot be empty")
    }
    if len(message) == 0 {
        return nil, fmt.Errorf("signed message cannot be empty")
    }

    sig, err := ed25519.NewKeyFromSeed(self[:]).Sign(rand.Reader, append([]byte(subject), message...), crypto.Hash(0))
    if err != nil {
        return nil, err
    }

    if len(sig) != 64 {
        return nil, fmt.Errorf("internal error in golang crypo: unexpected signature len")
    }

    var rr Signature
    copy(rr[:], sig);

    return &rr, nil;
}


// -- identity

func (self *Identity) String() string {
    return to_str(9, self[:]);
}

func (self *Identity) String58() string {
    return to_str58(9, self[:]);
}


func (self *Identity) XPublic() (*XPublic, error) {
    b, ok := x25519.EdPublicKeyToX25519(ed25519_.PublicKey(self[:]))
    if !ok {
        return nil, fmt.Errorf("invalid identity");
    }

    var r XPublic;
    copy(r[:], b[:])
    return &r, nil

}

func IdentityFromSecret(secret *Secret) *Identity {
    pkk := ed25519.NewKeyFromSeed(secret[:]).Public().(ed25519.PublicKey)
    var r Identity;
    copy(r[:], pkk[:])
    return &r;
}

func IdentityFromString(from string) (*Identity, error) {
    a, err := from_str(from, 9, 32)
    if err != nil {
        return nil, err;
    }
    if len(a) < 32 {
        return nil, fmt.Errorf("expected 32 bytes, got %d", len(a));
    }

    var r Identity;
    copy(r[:], a[:])
    return &r, nil;
}

// -- address


func XPublicFromSecret(from *XSecret) *XPublic {
    var base [32]byte
    copy(base[:], curve25519.Basepoint)

    var r XPublic;
    curve25519.ScalarMult((*[32]byte)(&r), (*[32]byte)(from), &base);
    return &r;
}

func XPublicFromString(from string) (*XPublic, error) {
    a, err := from_str(from, 6, 32)
    if err != nil {
        return nil, err;
    }
    if len(a) < 32 {
        return nil, fmt.Errorf("expected 32 bytes");
    }

    var r XPublic;
    copy(r[:], a[:])
    return &r, nil;
}

func (self *XPublic) String() string {
    return to_str(6, self[:]);
}

// -- secretkit

func (self *SecretKit) ToString() string {

    var b [64]byte;
    copy(b[0:],     self.Identity[:])
    copy(b[32:],    self.Network[:])

    return to_str(1, b[:]);
}

func SecretKitFromString(from string) (*SecretKit, error) {
    a, err := from_str(from, 1, 64)
    if err != nil {
        return nil, err;
    }
    if len(a) < 64 {
        return nil, fmt.Errorf("expected 64 bytes");
    }

    var r SecretKit;
    copy(r.Identity[:], a[:])
    copy(r.Network[:], a[32:])
    return &r, nil;
}

// -- sequence


func (self Sequence) String() string {
    return self.ToString()
}

func (self Sequence) ToString() string {

    var b bytes.Buffer
    var err = binary.Write(&b, binary.LittleEndian, self)
    if err != nil { panic(err)}


    var bb = b.Bytes()

    var ll = 8
    for i := 0; i < 8; i++ {
        if bb[7-i] == 0 {
            ll -= 1
        } else {
            break
        }
    }

    return to_str(11, bb[:ll]);
}

func SequenceFromString(from string) (Sequence, error) {
    a, err := from_str(from, 11, 0)
    if err != nil { return Sequence(0), err; }

    for ;len(a) < 8; {
        a = append(a, 0)
    }

    var v = binary.LittleEndian.Uint64(a)
    if err != nil { return Sequence(0), err; }

    return Sequence(v), nil
}

// -- message


func (self *Message) String() string {
    return self.ToString()
}

func (self *Message) ToString() string {

    var key = []byte(self.Key)

    if len(key) > 0xff {
        key = key[:0xff]
    }
    var l = uint8(len(key))
    var b bytes.Buffer
    b.Write([]byte{l})
    b.Write(key)
    b.Write(self.Value)

    return to_str(14, b.Bytes())
}

func MessageFromString(from string) (*Message, error) {
    a, err := from_str(from, 14, 0)
    if err != nil { return nil, err; }

    if len(a) < 2 {
        return nil, errors.New("cannot decode '"+from+"' : too small");
    }
    var keylen = int(a[0])
    if len(a) < 1 + keylen {
        return nil, errors.New("cannot decode '"+from+"' : too small");
    }

    return &Message{
        Key:    string(a[1:1+keylen]),
        Value:  a[1+keylen:],
    }, nil
}

// -- common

func from_str(from  string, expect_type uint8, expected_size int) ([]byte, error) {
    from = strings.TrimSpace(from)

    if len(from) < 3 {
        return []byte{}, errors.New("cannot decode '"+from+"' : too small");
    }

    if from[0] != 'c' && from[0] != '+' && from[0] != '=' {
        return []byte{}, errors.New("cannot decode '"+from+"' : not a b32");
    }

    b, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(from[1:])
    if err != nil {
        return nil, fmt.Errorf("base32 decoding error: %w",err)
    }

    if from[0] == '+' || from[0] == '=' {
        if (11 != expect_type) {
            return []byte{}, errors.New("expected " + type_string(expect_type) +
            " , but got " + type_string(11));
        }
        return b, nil;
    }

    if len(b) < 3 {
        return []byte{}, errors.New("cannot decode: too small");
    }

    if b[0] >> 4 != 1 {
        return []byte{}, errors.New("cannot decode: invalid version " + strconv.Itoa(int(b[0] >> 4)));
    }

    if ((b[0] & 0x0f) != expect_type) {
        return []byte{}, errors.New("expected " + type_string(expect_type) +
            " , but got " + type_string(b[0] & 0x0f));
    }

    for ;len(b) - 2 < expected_size; {
        var index = 1;
        b = append(b[:index+1], b[index:]...)
        b[index] = 0
    }


    var br = b[1:len(b)-1];
    var crc = crc8.Checksum(b[0:1], &crc8_table);
    crc = crc8.Update(crc, &crc8_table,  br);

    if crc != b[len(b)-1] {
        return []byte{}, errors.New("cannot decode: invalid checksum");
    }

    err = nullcheck(br);

    if err != nil {
        return []byte{}, err;
    }

    return br, nil;
}



func type_string(typ byte) string {
    switch typ {
        case 1  : return "SecretKit";
        case 3  : return "Secret";
        case 5  : return "RSASecret";
        case 6  : return "Address";
        case 8  : return "RSAPublic";
        case 9  : return "Identity";
        case 10 : return "Signature";
        case 11 : return "Sequence";
        case 14 : return "Message";
        default : return "unknown type " + strconv.Itoa(int(typ));
    }
}


// width=8 poly=0x4d init=0xff refin=true refout=true xorout=0xff check=0xd8
var crc8_table = crc8.Table([256]byte{
    0xea, 0xd4, 0x96, 0xa8, 0x12, 0x2c, 0x6e, 0x50, 0x7f, 0x41, 0x03, 0x3d,
    0x87, 0xb9, 0xfb, 0xc5, 0xa5, 0x9b, 0xd9, 0xe7, 0x5d, 0x63, 0x21, 0x1f,
    0x30, 0x0e, 0x4c, 0x72, 0xc8, 0xf6, 0xb4, 0x8a, 0x74, 0x4a, 0x08, 0x36,
    0x8c, 0xb2, 0xf0, 0xce, 0xe1, 0xdf, 0x9d, 0xa3, 0x19, 0x27, 0x65, 0x5b,
    0x3b, 0x05, 0x47, 0x79, 0xc3, 0xfd, 0xbf, 0x81, 0xae, 0x90, 0xd2, 0xec,
    0x56, 0x68, 0x2a, 0x14, 0xb3, 0x8d, 0xcf, 0xf1, 0x4b, 0x75, 0x37, 0x09,
    0x26, 0x18, 0x5a, 0x64, 0xde, 0xe0, 0xa2, 0x9c, 0xfc, 0xc2, 0x80, 0xbe,
    0x04, 0x3a, 0x78, 0x46, 0x69, 0x57, 0x15, 0x2b, 0x91, 0xaf, 0xed, 0xd3,
    0x2d, 0x13, 0x51, 0x6f, 0xd5, 0xeb, 0xa9, 0x97, 0xb8, 0x86, 0xc4, 0xfa,
    0x40, 0x7e, 0x3c, 0x02, 0x62, 0x5c, 0x1e, 0x20, 0x9a, 0xa4, 0xe6, 0xd8,
    0xf7, 0xc9, 0x8b, 0xb5, 0x0f, 0x31, 0x73, 0x4d, 0x58, 0x66, 0x24, 0x1a,
    0xa0, 0x9e, 0xdc, 0xe2, 0xcd, 0xf3, 0xb1, 0x8f, 0x35, 0x0b, 0x49, 0x77,
    0x17, 0x29, 0x6b, 0x55, 0xef, 0xd1, 0x93, 0xad, 0x82, 0xbc, 0xfe, 0xc0,
    0x7a, 0x44, 0x06, 0x38, 0xc6, 0xf8, 0xba, 0x84, 0x3e, 0x00, 0x42, 0x7c,
    0x53, 0x6d, 0x2f, 0x11, 0xab, 0x95, 0xd7, 0xe9, 0x89, 0xb7, 0xf5, 0xcb,
    0x71, 0x4f, 0x0d, 0x33, 0x1c, 0x22, 0x60, 0x5e, 0xe4, 0xda, 0x98, 0xa6,
    0x01, 0x3f, 0x7d, 0x43, 0xf9, 0xc7, 0x85, 0xbb, 0x94, 0xaa, 0xe8, 0xd6,
    0x6c, 0x52, 0x10, 0x2e, 0x4e, 0x70, 0x32, 0x0c, 0xb6, 0x88, 0xca, 0xf4,
    0xdb, 0xe5, 0xa7, 0x99, 0x23, 0x1d, 0x5f, 0x61, 0x9f, 0xa1, 0xe3, 0xdd,
    0x67, 0x59, 0x1b, 0x25, 0x0a, 0x34, 0x76, 0x48, 0xf2, 0xcc, 0x8e, 0xb0,
    0xd0, 0xee, 0xac, 0x92, 0x28, 0x16, 0x54, 0x6a, 0x45, 0x7b, 0x39, 0x07,
    0xbd, 0x83, 0xc1, 0xff,
});

func to_str(typ uint8, k []byte) string {


    var out bytes.Buffer;
    var b   bytes.Buffer

    if typ == 11 {
        out.WriteByte('+');
    } else {
        out.WriteByte('c')
        b.WriteByte(1 << 4 | typ);
    }

    b.Write(k);

    if typ != 11 {
        var crc = crc8.Checksum(b.Bytes()[0:1], &crc8_table);
        crc = crc8.Update(crc, &crc8_table, k);
        b.WriteByte(crc);
    }

    encoder := base32.NewEncoder(base32.StdEncoding.WithPadding(base32.NoPadding), &out);
    encoder.Write(b.Bytes())
    encoder.Close()

    return strings.Trim(string(out.Bytes()), "=")
}

func to_str58(typ uint8, k []byte) string {
    var b     bytes.Buffer

    b.WriteByte(8)
    b.WriteByte(typ)
    b.Write(k)

    b.WriteByte(broken_crc8(0, b.Bytes()))

    rr := base58.Encode(b.Bytes(), base58.BitcoinAlphabet)

    return rr;
}

// this is the equivalent of the broken rust code in v8
func broken_crc8(crc byte, data []byte) byte {
    for i := 0; i < len(data); i++ {
        if ((crc ^ data[i]) % 2 > 0) {
            crc = 84;
        } else {
            crc = 0;
        }
    }
    return crc;
}



func isnull(k []byte) bool {
    if len(k) < 1 {
        return true;
    }
    first := k[0];
    for i := 1; i < 32; i++ {
        if first != k[i] {
            return false;
        }
    }
    return true;
}

func nullcheck(k []byte) error {
    if isnull(k) {
        return errors.New("invalid ed25519: 32 identical bytes");
    }
    return nil;
}


