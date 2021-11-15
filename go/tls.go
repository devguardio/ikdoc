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
    "errors"
    "crypto/tls"
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
        Version:  3,
        SerialNumber: big.NewInt(1),
        Subject: pkix.Name{
            Organization:       []string{"identitykit"},
            CommonName:         base64.StdEncoding.EncodeToString(cakeyid[:]),
        },
        NotBefore:              notBefore,
        NotAfter:               notAfter,
        IsCA:                   true,
        BasicConstraintsValid:  true,
        KeyUsage:               x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
        ExtKeyUsage:            []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
        SubjectKeyId:           cakeyid[:],
        PublicKey:              self.ToGo(),
        PublicKeyAlgorithm:     x509.Ed25519,
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
        Version:  3,
        SerialNumber: big.NewInt(1),
        Subject: pkix.Name{
            Organization:           []string{"identitykit"},
            CommonName:             self.String(),
        },
        NotBefore:              notBefore,
        NotAfter:               notAfter,
        IsCA:                   true,
        BasicConstraintsValid:  true,
        KeyUsage:               x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
        ExtKeyUsage:            []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
        SubjectKeyId:           self[:],
        PublicKey:              self.ToGo(),
        PublicKeyAlgorithm:     x509.Ed25519,
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



func ClaimedPeerIdentity(c*tls.ConnectionState) Identity {
    // the claimed id ca is the last certificate
    var idCert = c.PeerCertificates[len(c.PeerCertificates)-1];
    var id Identity;

    pkey, ok := idCert.PublicKey.(ed25519.PublicKey);
    if !ok {
        panic(errors.New("tls: claimed identity not ed25519. this should have been cought by identity.VerifyPeerCertificate"));
    }

    copy(id[:], pkey[:]);
    return id;
}


func VerifyPeerCertificate (certificates [][]byte, verifiedChains [][]*x509.Certificate) error {

    certs := make([]*x509.Certificate, len(certificates))
    var err error
    for i, asn1Data := range certificates {
        if certs[i], err = x509.ParseCertificate(asn1Data); err != nil {
            return errors.New("tls: failed to parse client certificate: " + err.Error())
        }
    }
    if len(certs) == 0 {
        return errors.New("tls: client didn't provide a certificate")
    }


    // the claimed id ca is the last certificate

    var idCert = certs[len(certs)-1];

    pkey, ok := idCert.PublicKey.(ed25519.PublicKey);
    if !ok {
        return errors.New("tls: claimed identity not ed25519");
    }
    var id Identity;
    copy(id[:], pkey[:]);

    cacert, err := id.ToCertificate();
    if err != nil { return err }

    err = idCert.CheckSignatureFrom(cacert);
    if err != nil { return errors.New("failed checking if client presented root is signed by the claimed identity: " + err.Error()) }


    // now verify the first cert (for which the client has the key)
    // is signed by a chain leading to the claimed id ca

    var capool = x509.NewCertPool();
    //TODO why does this not work? it shouldnt make a difference,
    // because the idCert IS the thing we're checking,
    // but i'd still prefer if we didnt use remote input

    //capool.AddCert(cacert);
    capool.AddCert(idCert);

    var impool = x509.NewCertPool();

    if len(certs) > 1 {
        for _,im := range certs[1:len(certs)-1] {
            impool.AddCert(im);
        }
    }

    opts := x509.VerifyOptions{
        Roots:          capool,
        Intermediates:  impool,
        CurrentTime:    time.Now(),
        KeyUsages:      []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
    }

    _ , err = certs[0].Verify(opts)
    if err != nil {
        return errors.New("tls: failed to verify client certificate: " + err.Error())
    }

    return nil
}


func NewTlsClient(vault VaultI) (*tls.Config, error) {

    key, err := Vault().ExportSecret()
    if err != nil { return nil, err }

    pub, err := vault.Identity();
    if err != nil { return nil, err }

    cert, err := pub.ToCertificate();
    if err != nil { return nil, err }

    der, err := vault.SignCertificate(cert, pub);
    if err != nil { return nil, err }

    tcert := tls.Certificate{
        Certificate: [][]byte{der},
        PrivateKey: key.ToGo(),
    }

    tlsconfig := &tls.Config{
        RootCAs:        x509.NewCertPool(),
        Certificates:   []tls.Certificate{tcert},
    }

    return tlsconfig, nil
}
