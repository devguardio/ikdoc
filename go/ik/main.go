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
    "crypto/tls"
    "net/http"
    "io/ioutil"
    "bufio"
)

func main() {
    log.SetFlags(log.Lshortfile);

    var rootCmd = cobra.Command{
        Use:        "identitykit",
        Short:      "\ncryptographic identity toolkit",
        Version:    "1",
    }

    var usersa = false
    rootCmd.PersistentFlags().BoolVarP(&usersa, "rsa", "r", false, "use rsa instead of ed25519")



    var sqCmd = &cobra.Command{
        Use:        "anchor",
        Aliases:    []string{"a"},
        Short:      "generic sequential anchor",
    }
    rootCmd.AddCommand(sqCmd);

    sqNewCmd := &cobra.Command{
        Use:        "new <anchorname> <identity>",
        Short:      "create a new anchor with an initially trusted identity",
        Args:       cobra.MinimumNArgs(2),
        Run: func(cmd *cobra.Command, args []string) {

            var argIdentity = args[1]
            id, err := identity.IdentityFromString(argIdentity)
            if err != nil { panic(fmt.Errorf("%s : %w", argIdentity, err)) }

            err = identity.NewAnchor(identity.Vault(), args[0], id)
            if err != nil { panic(err) }
        },
    }
    sqCmd.AddCommand(sqNewCmd)

    var argAdvanceQuorum    uint
    var argSignQuorum       uint

    sqAddCmd := &cobra.Command{
        Use:        "add <anchorname> <identity> [ -a <advance-quorum> ] [ -s <sign-quorum> ]",
        Short:      "add an identity to anchor",
        Args:       cobra.MinimumNArgs(2),
        Run: func(cmd *cobra.Command, args []string) {

            var argIdentity = args[1]
            id, err := identity.IdentityFromString(argIdentity)
            if err != nil { panic(fmt.Errorf("%s : %w", argIdentity, err)) }

            anchor, err := identity.AppendRemoveAnchor(identity.Vault(), args[0], id, false, argAdvanceQuorum, argSignQuorum)
            if err != nil { panic(err) }

            fmt.Println(anchor.Sequence);
        },
    }
    sqAddCmd.Flags().UintVarP(&argAdvanceQuorum,  "advance-quorum", "a", 0, "number of members required to forward the sequence");
    sqAddCmd.Flags().UintVarP(&argSignQuorum,     "signature-quorum", "s", 0, "number of members required to consider a message signed by anchor");
    sqCmd.AddCommand(sqAddCmd)


    sqRmCmd := &cobra.Command{
        Use:        "remove <anchorname> <identity> [ -a <advance-quorum> ] [ -s <sign-quorum> ]",
        Aliases:    []string{"rm", "del"},
        Short:      "remove an identity from  anchor",
        Args:       cobra.MinimumNArgs(2),
        Run: func(cmd *cobra.Command, args []string) {

            var argIdentity = args[1]
            id, err := identity.IdentityFromString(argIdentity)
            if err != nil { panic(fmt.Errorf("%s : %w", argIdentity, err)) }

            anchor, err := identity.AppendRemoveAnchor(identity.Vault(), args[0], id, true, argAdvanceQuorum, argSignQuorum)
            if err != nil { panic(err) }

            fmt.Println(anchor.Sequence);
        },
    }
    sqRmCmd.Flags().UintVarP(&argAdvanceQuorum,  "advance-quorum", "a", 0, "number of members required to forward the sequence");
    sqRmCmd.Flags().UintVarP(&argSignQuorum,     "signature-quorum", "s", 0, "number of members required to consider a message signed by anchor");
    sqCmd.AddCommand(sqRmCmd)

    var mCmd = &cobra.Command{
        Use:        "msg",
        Aliases:    []string{"m"},
        Short:      "generic signed messages",
    }
    rootCmd.AddCommand(mCmd);

    mCmd.AddCommand(&cobra.Command{
        Use:        "sign <filename>",
        Short:      "sign a file and add sig to <filename>.iksig in the same directory",
        Args:       cobra.MinimumNArgs(1),
        Run: func(cmd *cobra.Command, args []string) {

            b, err := ioutil.ReadFile(args[0])
            if err != nil { panic(err) }

            sig, err := identity.Vault().Sign("iksig", b)
            if err != nil { panic(err) }

            f, err := os.OpenFile(args[0] + ".iksig", os.O_RDWR | os.O_CREATE | os.O_APPEND, 0755)
            if err != nil { panic(fmt.Errorf("%s : %w", args[0] + ".iksig", err)) }

            _, err = f.Write([]byte(sig.String() + "\n"))
            if err != nil { panic(fmt.Errorf("%s : %w", args[0] + ".iksig", err)) }
        },
    });



    var argIdentity string
    var argAnchor   string
    verifyCmd := &cobra.Command{
        Use:        "verify <filename> [ -i <identity> |  -a <anchor> ]",
        Short:      "verify a file is signed by an identity or anchor using <filename>.iksig in the same directory",
        Args:       cobra.MinimumNArgs(1),
        Run: func(cmd *cobra.Command, args []string) {

            var err error
            var anchor *identity.Anchor

            if argAnchor != "" {
                anchor, err = identity.LoadAnchor(identity.Vault(),  argAnchor)
                if err != nil { panic(fmt.Errorf("%s : %w", argAnchor, err)) }
            } else if argIdentity != "" {
                id, err := identity.IdentityFromString(argIdentity)
                if err != nil { panic(fmt.Errorf("%s : %w", argIdentity, err)) }

                anchor = &identity.Anchor{
                    Trust:              []identity.Identity{*id},
                    SignatureQuorum:    1,
                    AdvanceQuorum:      1,
                }
            } else {
                panic("-i or -a required")
            }

            b, err := ioutil.ReadFile(args[0])
            if err != nil { panic(fmt.Errorf("%s : %w", args[0], err)) }

            sf, err := os.Open(args[0] + ".iksig")
            if err != nil { panic(fmt.Errorf("%s : %w", args[0] + ".iksig", err)) }
            scanner := bufio.NewScanner(sf)

            var sigs = []identity.Signature{}
            for scanner.Scan() {
                var sig *identity.Signature
                sig, err = identity.SignatureFromString(scanner.Text())
                if err != nil { continue }
                sigs = append(sigs, *sig)
            }

            err = anchor.Verify(false, "iksig", b, sigs)
            if err != nil {
                fmt.Printf("%s : %v\n", args[0] + ".iksig", err);
                os.Exit(2)
            }
        },
    };
    verifyCmd.Flags().StringVarP(&argIdentity,  "identity", "i",  "", "public identity")
    verifyCmd.Flags().StringVarP(&argAnchor,    "anchor",   "a",  "", "anchor")
    mCmd.AddCommand(verifyCmd);


    compat := &cobra.Command{
        Use:        "convert <id>",
        Short:      "legacy conversion commands",
        Aliases:    []string{"cv", "conv"},
    }
    compat.AddCommand(&cobra.Command{
        Use:        "id32to58 <id>",
        Short:      "convert a b32 identity to a legacy b58",
        Args:       cobra.MinimumNArgs(1),
        Run: func(cmd *cobra.Command, args []string) {
            id, err := identity.IdentityFromString(args[0])
            if err != nil { panic(err) }
            fmt.Println(id.String58())
        },
    });
    rootCmd.AddCommand(compat);

    rootCmd.AddCommand(&cobra.Command{
        Use:        "identity ",
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
        Aliases:  []string{"xp", "addr"},
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

    tlsCmd := &cobra.Command{
        Use:        "tls",
        Short:      "x509 mode",
        Aliases:    []string{"x509"},
    }
    rootCmd.AddCommand(tlsCmd);

    tlsCmd.AddCommand(&cobra.Command{
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

    tlsCmd.AddCommand(&cobra.Command{
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

                pub,err := key.Identity();
                if err != nil { panic(err) }
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

    tlsCmd.AddCommand(cmdCert);





    tlsCmd.AddCommand(&cobra.Command{
        Use:    "serve",
        Short:  "launch an https test server with a certificate bundle signed by the vault",
        Run: func(cmd *cobra.Command, args []string) {

            var vault = identity.Vault();
            var tlsconfig = &tls.Config{
                InsecureSkipVerify: true,
                MaxVersion:         tls.VersionTLS12,
                GetCertificate: func(helo*tls.ClientHelloInfo) (*tls.Certificate, error) {

                    log.Println("SNI: ", helo.ServerName);

                    var notBefore = time.Now().Add(-1 * time.Hour)
                    var notAfter  = notBefore.Add(time.Hour * 87600)

                    cert := &x509.Certificate{
                        SerialNumber: big.NewInt(1),
                        Subject: pkix.Name{
                            Organization:           []string{"identitykit"},
                            CommonName:             helo.ServerName,
                        },
                        NotBefore:              notBefore,
                        NotAfter:               notAfter,
                        IsCA:                   false,
                        KeyUsage:               x509.KeyUsageDigitalSignature,
                        ExtKeyUsage:            []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
                    }

                    key, err := identity.CreateSecret();
                    if err != nil { panic(err) }

                    pub, err := key.Identity();
                    if err != nil { panic(err) }
                    cert.SubjectKeyId = pub[:];

                    der, err := vault.SignCertificate(cert, pub);
                    if err != nil { panic(err) }

                    return &tls.Certificate{
                        PrivateKey: key.ToGo(),
                        Certificate: [][]byte{der},
                    }, nil
                },
                ClientAuth: tls.RequireAnyClientCert,
                VerifyPeerCertificate: identity.VerifyPeerCertificate,
            };

            server := http.Server{
                Addr:      "0.0.0.0:8443",
                Handler:   http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                    id := identity.ClaimedPeerIdentity(r.TLS);
                    fmt.Fprintf(w, "Hello, %s\n", id.String())
                }),
                TLSConfig: tlsconfig,
            }
            log.Println("listening on 0.0.0.0:8443");
            err := server.ListenAndServeTLS("", "")
            if err != nil { panic(err) }
        },
    });

    if err := rootCmd.Execute(); err != nil {
        os.Exit(1);
    }
}
