package identity

import (
    "bytes"
    "crypto"
    "crypto/ed25519"
    "crypto/rand"
    "crypto/rsa"
    "crypto/sha256"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/pem"
    "encoding/asn1"
    "math/big"
    "time"
    "fmt"
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

func makeCA(priv crypto.Signer) ([]byte, error) {

    var notBefore = time.Now().Add(-1 * time.Hour)
    var notAfter = notBefore.Add(time.Hour * 2500000)

    cakeyid, err := keyid(priv.Public())
    if err != nil { return nil, err}

    template := x509.Certificate{
        SerialNumber: big.NewInt(1),
        Subject: pkix.Name{
            Organization:           []string{"identitykit"},
            OrganizationalUnit:     []string{base64.StdEncoding.EncodeToString(cakeyid)},
        },
        NotBefore: notBefore,
        NotAfter:  notAfter,
        IsCA:                   true,
        KeyUsage:               x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
        ExtKeyUsage:            []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
        BasicConstraintsValid:  true,
        SubjectKeyId:           cakeyid,
    }
    derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template,  priv.Public(), priv)
    if err != nil { return nil, err}

    var out bytes.Buffer
    err = pem.Encode(&out, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes});
    if err != nil { return nil, err}

    return (out.Bytes()), nil
}


func makeCert(spub crypto.PublicKey, capriv crypto.Signer, names []string) ([]byte, error) {

    var notBefore = time.Now().Add(-1 * time.Hour)
    var notAfter = notBefore.Add(2 * time.Hour)

    serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
    serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
    if err != nil { return nil, err}


    cakeyid, err := keyid(capriv.Public())
    if err != nil { return nil, err}

    parent := x509.Certificate {
        SerialNumber: big.NewInt(1),
        Subject: pkix.Name{
            Organization:           []string{"identitykit"},
            OrganizationalUnit:     []string{base64.StdEncoding.EncodeToString(cakeyid)},
        },
        NotBefore: notBefore,
        NotAfter:  notAfter,
        IsCA:                   true,
        KeyUsage:               x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
        ExtKeyUsage:            []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
        BasicConstraintsValid:  true,
        SubjectKeyId:           cakeyid,
    }


    cn := ""
    if len(names) > 0 {
        cn = names[0]
    }

    template := x509.Certificate{
        SerialNumber: serialNumber,
        Subject: pkix.Name{
            Organization:           []string{"identitykit"},
            CommonName:             cn,
        },
        NotBefore: notBefore,
        NotAfter:  notAfter,

        KeyUsage:               x509.KeyUsageDigitalSignature,
        ExtKeyUsage:            []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
        BasicConstraintsValid:  true,
        DNSNames:               names,
    }
    derBytes, err := x509.CreateCertificate(rand.Reader, &template, &parent,  spub, capriv)
    if err != nil { return nil, err}


    var out bytes.Buffer

    err = pem.Encode(&out, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes});
    if err != nil { return nil, err}

    return (out.Bytes()), nil
}


func keyid(spub crypto.PublicKey) ([]byte, error) {
    switch spub := spub.(type) {
        case *rsa.PublicKey:
            bytes, err := asn1.Marshal(pkcs1PublicKey{
                N: spub.N,
                E: spub.E,
            })
            if err != nil { return nil, err }
            sum:= sha256.Sum256(bytes)
            return sum[:], nil
        case ed25519.PublicKey:
            return spub, nil
        default:
            return nil, fmt.Errorf("keyid: unexpected %T", spub)
    }
}

type pkcs1PublicKey struct {
	N *big.Int
	E int
}
