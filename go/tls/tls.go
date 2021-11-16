package tls

import (
    "github.com/devguardio/identity/go"
    "crypto/ed25519"
    "crypto/x509"
    "time"
    "errors"
    "crypto/tls"
)


func ClaimedPeerIdentity(c*tls.ConnectionState) identity.Identity {
    // the claimed id ca is the last certificate
    var idCert = c.PeerCertificates[len(c.PeerCertificates)-1];
    var id identity.Identity;

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
    var id identity.Identity;
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


func NewTlsClient(vault identity.VaultI) (*tls.Config, error) {

    key, err := vault.ExportSecret()
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
