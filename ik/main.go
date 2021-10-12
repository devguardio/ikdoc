package main

import (
    "github.com/spf13/cobra"
    "github.com/devguardio/identity/go"
    "log"
    "fmt"
    "os"
    "encoding/pem"
    "crypto/x509"
    "math/big"
    "time"
    "crypto/x509/pkix"
    "net"
)

func main() {
    log.SetFlags(log.Lshortfile);

    var rootCmd = cobra.Command{
        Use:        "identitykit",
        Short:      "\ndevguard identity managment",
        Version:    "1",
    }

    var usersa = false
    rootCmd.PersistentFlags().BoolVarP(&usersa, "rsa", "r", false, "use rsa instead of ed25519")


    rootCmd.AddCommand(&cobra.Command{
        Use:        "identity",
        Aliases:    []string{"id"},
        Short:      "print my identity",
        Run: func(cmd *cobra.Command, args []string) {
            if usersa {
                id, err := identity.Vault().RSAPublic()
                if err != nil { panic(err) }
                fmt.Println(id)
            } else {
                id, err := identity.Vault().Identity()
                if err != nil { panic(err) }
                fmt.Println(id)
            }
        },
    });

    rootCmd.AddCommand(&cobra.Command{
        Use:    "address",
        Aliases:  []string{"xp"},
        Short:  "print my DH address",
        Run: func(cmd *cobra.Command, args []string) {
            if usersa {
                panic("rsa doesn't work with diffie-hellman")
            } else {
                id, err := identity.Vault().XPublic()
                if err != nil { panic(err) }
                fmt.Println(id)
            }
        },
    });

    rootCmd.AddCommand(&cobra.Command{
        Use:    "init",
        Short:  "initialize empty vault",
        Run: func(cmd *cobra.Command, args []string) {
            err := identity.Vault().Init(true)
            if err != nil { panic(err) }

            id, err := identity.Vault().Identity()
            if err != nil { panic(err) }
            fmt.Println(id)
        },
    });


    rootCmd.AddCommand(&cobra.Command{
        Use:    "pem",
        Short:  "export secret as PKCS8",
        Run: func(cmd *cobra.Command, args []string) {
            if usersa {
                p, err := identity.Vault().ExportRSASecret()
                if err != nil { panic(err) }
                pem, err := p.ToPem()
                if err != nil { panic(err) }
                os.Stdout.Write([]byte(pem))
            } else {
                p, err := identity.Vault().ExportSecret()
                if err != nil { panic(err) }
                pem, err := p.ToPem()
                if err != nil { panic(err) }
                os.Stdout.Write([]byte(pem))
            }
        },
    });

    rootCmd.AddCommand(&cobra.Command{
        Use:    "ca",
        Short:  "export public key as x509 cert",
        Run: func(cmd *cobra.Command, args []string) {
            var vault = identity.Vault();

            if usersa {
                pub, err := vault.RSAPublic();
                if err != nil { panic(err) }

                cert, err := pub.ToCertificate();
                if err != nil { panic(err) }

                der, err := vault.SignRSACertificate(cert, pub);
                if err != nil { panic(err) }

                err = pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE", Bytes: der});
                if err != nil { panic(err) }
            } else {
                pub, err := vault.Identity();
                if err != nil { panic(err) }

                cert, err := pub.ToCertificate();
                if err != nil { panic(err) }

                der, err := vault.SignCertificate(cert, pub);
                if err != nil { panic(err) }

                err = pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE", Bytes: der});
                if err != nil { panic(err) }
            }
        },
    });


    var altips []string
    var altdns []string

    var cmdCert = &cobra.Command{
        Use:    "cert <subject>",
        Short:  "create a new key/cert bundle, signed by the vault",
        Args:   cobra.MinimumNArgs(1),
        Run: func(cmd *cobra.Command, args []string) {
            var vault = identity.Vault();

            var altipsi = make([]net.IP, len(altips))
            for i,_ := range(altips) {
                altipsi[i] = net.ParseIP(altips[i])
                if altipsi[i] == nil {
                    panic("cannot parse --ip " + altips[i]);
                }
            }

            var notBefore = time.Now().Add(-1 * time.Hour)
            var notAfter  = notBefore.Add(time.Hour * 87600)

            cert := &x509.Certificate{
                SerialNumber: big.NewInt(1),
                Subject: pkix.Name{
                    Organization:           []string{"identitykit"},
                    CommonName:             args[0],
                },
                NotBefore:              notBefore,
                NotAfter:               notAfter,
                IsCA:                   false,
                KeyUsage:               x509.KeyUsageDigitalSignature,
                ExtKeyUsage:            []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
                DNSNames:               altdns,
                IPAddresses:            altipsi,
            }

            if usersa {
                key, err := identity.CreateRSASecret(2048);
                if err != nil { panic(err) }

                pub := key.RSAPublic();

                der, err := vault.SignRSACertificate(cert, pub);
                if err != nil { panic(err) }

                err = pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE", Bytes: der});
                if err != nil { panic(err) }

                pem, err := key.ToPem()
                if err != nil { panic(err) }
                os.Stdout.Write([]byte(pem))

            } else {
                key, err := identity.CreateSecret();
                if err != nil { panic(err) }

                pub := key.Identity();
                cert.SubjectKeyId = pub[:];

                der, err := vault.SignCertificate(cert, pub);
                if err != nil { panic(err) }

                err = pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE", Bytes: der});
                if err != nil { panic(err) }

                pem, err := key.ToPem()
                if err != nil { panic(err) }
                os.Stdout.Write([]byte(pem))
            }
        },
    };

    cmdCert.Flags().StringSliceVar(&altips, "ip",  []string{}, "Subject Alternate Name Ip Address")
    cmdCert.Flags().StringSliceVar(&altdns, "dns", []string{}, "Subject Alternate Name DNS Name")

    rootCmd.AddCommand(cmdCert);

    /*


    rootCmd.AddCommand(&cobra.Command{
        Use:    "tlsserver",
        Short:  "launch a test https server with a certificate bundle signed by the vault",
        Run: func(cmd *cobra.Command, args []string) {

            var tlsconfig = &tls.Config{
                InsecureSkipVerify: true,
                MaxVersion:         tls.VersionTLS12,
                GetCertificate: func(helo*tls.ClientHelloInfo) (*tls.Certificate, error) {

                    log.Println("SNI: ", helo.ServerName);

                    if usersa {
                        key, err := identity.CreateRSASecret(2048);
                        if err != nil { panic(err) }

                        der, err := identity.Vault().MakeRSACert(key.RSAPublic(), []string{helo.ServerName})
                        if err != nil { panic(err) }

                        return &tls.Certificate{
                            PrivateKey: key.ToGo(),
                            Certificate: [][]byte{der},
                        }, nil

                    } else {
                        key, err := identity.CreateSecret();
                        if err != nil { panic(err) }

                        der, err := identity.Vault().MakeCert(key.Identity(), []string{helo.ServerName})
                        if err != nil { panic(err) }

                        return &tls.Certificate{
                            PrivateKey: key.ToGo(),
                            Certificate: [][]byte{der},
                        }, nil
                    }
                },
                ClientAuth: tls.RequireAnyClientCert,
                VerifyPeerCertificate: func(certificates [][]byte, verifiedChains [][]*x509.Certificate) error {

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

                    // note that we totally ignore the chain.
                    // TLS clients usually assume the server and client chain have the same "chain"
                    // so it might send that, but certainly not any chain actually relevant to the client.
                    // So instead we must enforce that the client cert is self signed.

                    var idCert = certs[0];

                    pkey, ok := idCert.PublicKey.(ed25519.PublicKey);
                    if !ok {
                        return errors.New("tls: claimed identity not ed25519");
                    }
                    var id identity.Identity;
                    copy(id[:], pkey[:]);

                    // check self signature
                    err = idCert.CheckSignatureFrom(idCert);
                    if err != nil { return err }

                    // addtionally verify that the thing using whatever golang does.
                    // probably useless for our purpose, but why not

                    var notBefore = time.Now().Add(-1 * time.Hour)
                    var notAfter = notBefore.Add(2 * time.Hour)

                    var ca = x509.NewCertPool();
                    cac := &x509.Certificate{
                        Version:                3,
                        PublicKey:              pkey,
                        PublicKeyAlgorithm:     x509.Ed25519,
                        SerialNumber: big.NewInt(1),
                        Subject: pkix.Name{
                            Organization:           []string{"identitykit"},
                            OrganizationalUnit:     []string{base64.StdEncoding.EncodeToString(id[:])},
                        },
                        NotBefore: notBefore,
                        NotAfter:  notAfter,
                        IsCA:                   true,
                        KeyUsage:               x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
                        ExtKeyUsage:            []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
                        BasicConstraintsValid:  true,
                        SubjectKeyId:           id[:],
                    };
                    ca.AddCert(cac);

                    // note that this verifies ok for single cert, even if its not self signed,
                    // so i'm not even sure what the point of checking this is.
                    opts := x509.VerifyOptions{
                        Roots:          ca,
                        CurrentTime:    time.Now(),
                        KeyUsages:      []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
                    }

                    _ , err = certs[0].Verify(opts)
                    if err != nil {
                        return errors.New("tls: failed to verify client certificate: " + err.Error())
                    }


                    log.Println("verified identity: ", id.String());



                    return nil
                },

            };

            server := http.Server{
                Addr:      "0.0.0.0:8443",
                Handler:   http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                    fmt.Fprintf(w, "Hello, %q", r.URL.Path)
                }),
                TLSConfig: tlsconfig,
            }
            log.Println("listening on 0.0.0.0:8443");
            err := server.ListenAndServeTLS("", "")
            if err != nil { panic(err) }
        },
    });

    */

    if err := rootCmd.Execute(); err != nil {
        os.Exit(1);
    }
}
