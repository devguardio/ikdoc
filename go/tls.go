package identity

import (
    "crypto/x509"
    "encoding/pem"
    "crypto/ed25519"
    "crypto/rsa"
    "bytes"
    "crypto"
    "crypto/x509/pkix"
    "time"
    "crypto/rand"
    "math/big"
)




func (self *RSASecret) ToPem() ([]byte, error) {

    var p = (*rsa.PrivateKey)(self)
    var privBytes, err = x509.MarshalPKCS8PrivateKey(p)
    if err != nil { return nil, err }

    var out bytes.Buffer
    err = pem.Encode(&out, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes});
    if err != nil { return nil, err }

    return (out.Bytes()), nil
}

func (self *Secret) ToPem() ([]byte, error) {

    var p = ed25519.NewKeyFromSeed(self[:])
    var privBytes, err = x509.MarshalPKCS8PrivateKey(p)
    if err != nil { return nil, err }

    var out bytes.Buffer
    err = pem.Encode(&out, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes});
    if err != nil { return nil, err }

    return out.Bytes(), nil
}


func (self *Secret) MakeTLS() ([]byte, error) {
    return makeTlsCert(ed25519.NewKeyFromSeed(self[:]))
}

func (self *RSASecret) MakeTLS() ([]byte, error) {
    return makeTlsCert((*rsa.PrivateKey)(self))
}

func makeTlsCert(priv crypto.Signer) ([]byte, error) {
    // ECDSA, ED25519 and RSA subject keys should have the DigitalSignature
    // KeyUsage bits set in the x509.Certificate template
    keyUsage := x509.KeyUsageDigitalSignature

    var notBefore = time.Now()
    var notAfter = notBefore.Add(time.Minute)

    serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
    serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
    if err != nil { return nil, err}

    template := x509.Certificate{
        SerialNumber: serialNumber,
        Subject: pkix.Name{
            Organization: []string{"Acme Co"},
        },
        NotBefore: notBefore,
        NotAfter:  notAfter,

        KeyUsage:              keyUsage,
        ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
        BasicConstraintsValid: true,
    }
    derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template,  priv.Public(), priv)
    if err != nil { return nil, err}

    var out bytes.Buffer
    err = pem.Encode(&out, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes});
    if err != nil { return nil, err}

    return (out.Bytes()), nil
}


