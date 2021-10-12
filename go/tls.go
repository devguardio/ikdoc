package identity

import (
    "bytes"
    "crypto"
    "crypto/ed25519"
    "crypto/rsa"
    "crypto/sha1"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/pem"
    "encoding/asn1"
    "math/big"
    "time"
    "encoding/base64"
)


func (self *Secret) ToGo() crypto.Signer{
    var p = ed25519.NewKeyFromSeed(self[:])
    return p
}

func (self *RSASecret) ToGo() crypto.Signer{
    return (*rsa.PrivateKey)(self)
}

func (self *Identity) ToGo() crypto.PublicKey {
    var p = ed25519.PublicKey(self[:])
    return p
}

func (self *RSAPublic) ToGo() crypto.PublicKey {
    return (*rsa.PublicKey)(self)
}

func (self *RSASecret) ToPem() ([]byte, error) {

    var privBytes, err = x509.MarshalPKCS8PrivateKey(self.ToGo())
    if err != nil { return nil, err }

    var out bytes.Buffer
    err = pem.Encode(&out, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes});
    if err != nil { return nil, err }

    return (out.Bytes()), nil
}

func (self *Secret) ToPem() ([]byte, error) {

    var privBytes, err = x509.MarshalPKCS8PrivateKey(self.ToGo())
    if err != nil { return nil, err }

    var out bytes.Buffer
    err = pem.Encode(&out, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes});
    if err != nil { return nil, err }

    return out.Bytes(), nil
}

type CertOpts struct {
    DNSNames []string
}

func (self *RSAPublic) ToCertificate(opts... CertOpts) (*x509.Certificate, error) {
    pkbytes, err := asn1.Marshal(pkcs1PublicKey{
        N: self.N,
        E: self.E,
    })
    if err != nil { return nil, err }
    cakeyid := sha1.Sum(pkbytes)

    var notBefore = time.Now().Add(-1 * time.Hour)
    var notAfter = notBefore.Add(time.Hour * 2000000)

    c := x509.Certificate{
        SerialNumber: big.NewInt(1),
        Subject: pkix.Name{
            Organization:       []string{"identitykit"},
            CommonName:         base64.StdEncoding.EncodeToString(cakeyid[:]),
        },
        NotBefore:              notBefore,
        NotAfter:               notAfter,
        IsCA:                   true,
        KeyUsage:               x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
        ExtKeyUsage:            []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
        SubjectKeyId:           cakeyid[:],
    }

    for _,opt := range opts {
        c.DNSNames = append(c.DNSNames, opt.DNSNames...);
    }

    return &c, nil;
}

func (self *Identity) ToCertificate(opts ... CertOpts) (*x509.Certificate, error) {

    var notBefore = time.Now().Add(-1 * time.Hour)
    var notAfter = notBefore.Add(time.Hour * 1000000)

    c:= x509.Certificate{
        SerialNumber: big.NewInt(1),
        Subject: pkix.Name{
            Organization:           []string{"identitykit"},
            CommonName:             self.String(),
        },
        NotBefore:              notBefore,
        NotAfter:               notAfter,
        IsCA:                   true,
        KeyUsage:               x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
        ExtKeyUsage:            []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
        SubjectKeyId:           self[:],
    }

    for _,opt := range opts {
        c.DNSNames = append(c.DNSNames, opt.DNSNames...);
    }
    return &c, nil;
}


type pkcs1PublicKey struct {
	N *big.Int
	E int
}
