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
    "github.com/fatih/color"
    "bytes"
    "path/filepath"
    "strings"
    "crypto/sha256"
    "io"
    "crypto/subtle"
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

    rootCmd.AddCommand(&cobra.Command{
        Use:        "dumpdoc <filename>",
        Short:      "dump ikdoc as text repr",
        Args:       cobra.MinimumNArgs(1),
        Run: func(cmd *cobra.Command, args []string) {

            f, err := os.Open(args[0])
            if err != nil { panic(fmt.Errorf("%s : %w", args[0], err)) }

            _ , err = identity.ReadDocument(f, identity.DocumentOptDump{Writer: os.Stdout})
            if err != nil { panic(fmt.Errorf("%s : %w", args[0], err)) }
        },
    })

    var argAnon     bool
    var argDetached []string
    var argParent   string
    var argOutfile  string
    signCmd := &cobra.Command{
        Use:        "sign <filename> [<filename>  ...] --detached <filename>  [<filename> ...]",
        Short:      "sign files and pack into a <filename>.ikdoc",
        Run: func(cmd *cobra.Command, args []string) {

            var vault = identity.Vault()

            id, err:= vault.Identity()
            if err != nil { panic(err) }

            doc := &identity.Document {}

            if argParent != "" {
                f, err := os.Open(argParent)
                if err != nil { panic(fmt.Errorf("%s : %w", argParent, err)) }

                parent, err := identity.ReadDocument(f)
                if err != nil { panic(fmt.Errorf("%s : %w", argParent, err)) }

                doc = parent.NewSequence();
            }
            for _, n := range args {
                if argOutfile == "" {
                    argOutfile = n + ".ikdoc"
                }
                b, err := ioutil.ReadFile(n)
                if err != nil { panic(err) }
                err = doc.WithAttached(b, filepath.Base(n))
                if err != nil { panic(err) }
            }
            for _, n := range argDetached {
                if argOutfile == "" {
                    argOutfile = n + ".ikdoc"
                }
                f, err := os.Open(n)
                if err != nil { panic(err) }
                err = doc.WithDetached(f, filepath.Base(n))
                if err != nil { panic(err) }
            }

            if !argAnon {
                doc.Anchors = []identity.Identity{*id}
            }

            b, err := doc.EncodeAndSign(vault);
            if err != nil { panic(fmt.Errorf("%s : %w", args[0] + ".ikdoc", err)) }

            f, err := os.OpenFile(args[0] + ".ikdoc", os.O_RDWR | os.O_CREATE | os.O_EXCL, 0755)
            if err != nil { panic(fmt.Errorf("%s : %w", args[0] + ".ikdoc", err)) }

            _, err = f.Write(b)
            if err != nil { panic(err) }
        },
    }
    signCmd.Flags().StringArrayVarP(&argDetached, "detached", "d",  []string{}, "do not embedd the document")
    signCmd.Flags().BoolVarP(&argAnon,          "anon",     "n",  false, "do not reveal signee (also prevents sequencing)")
    signCmd.Flags().StringVarP(&argParent,      "parent",   "p",  "", "document follows a previous document in a sequence")
    rootCmd.AddCommand(signCmd);


    var argIdentity string
    verifyCmd := &cobra.Command{
        Use:        "verify <filename> [ -i <identity> |  -p <parent> ]",
        Short:      "verify an ikdoc is signed by an identity or sequence",
        Args:       cobra.MinimumNArgs(1),
        Run: func(cmd *cobra.Command, args []string) {

            var doc *identity.Document

            if argParent != "" {
                f, err := os.Open(argParent)
                if err != nil { panic(fmt.Errorf("%s : %w", argParent, err)) }

                precedent, err := identity.ReadDocument(f)
                if err != nil { panic(fmt.Errorf("%s : %w", argParent, err)) }

                b, err := os.ReadFile(args[0])
                if err != nil { panic(fmt.Errorf("%s : %w", args[0], err)) }

                doc, err = precedent.VerifySuccessor(b, identity.DocumentOptDump{Writer: os.Stdout})
                if err != nil {
                    fmt.Printf("%s : %v\n", args[0], err);
                    os.Exit(2)
                }

            } else if argIdentity != "" {

                id, err := identity.IdentityFromString(argIdentity)
                if err != nil { panic(fmt.Errorf("%s : %w", argIdentity, err)) }

                b, err := os.ReadFile(args[0])
                if err != nil { panic(fmt.Errorf("%s : %w", args[0], err)) }

                doc, err = identity.ReadDocument(bytes.NewReader(b))
                if err != nil { panic(err) }

                err = doc.Verify()
                if err != nil { panic(err) }

                var match = false
                for _, sig := range doc.Signatures {
                    if sig.Verify("ikdoc", b[:doc.SignedSize], id) {
                        match = true
                        break;
                    }
                }

                if match {
                    fmt.Printf("%s %s\n", color.GreenString("✔ signed"), id.String())
                } else {
                    fmt.Printf("%s %s\n", color.RedString  ("✖ nosign"),  id.String())
                    os.Exit(2)
                }

            } else {
                panic("-i or -p required")
            }


            for _,v := range doc.Detached {
                if strings.Contains(v.Name, "/") {
                    // illegal, just ignore
                    continue
                }
                rel := filepath.Join(args[0], "..", v.Name)

                f, err := os.Open(rel)
                if err != nil {
                    fmt.Printf("%s %s : %s\n", color.RedString("✖ detach"), v.Name, err);
                    continue
                }

                h := sha256.New()
                h.Write([]byte(v.Name))
                size, err := io.Copy(h, f);
                if err != nil { panic(fmt.Errorf("%s : %w", rel, err)) }

                if subtle.ConstantTimeCompare(v.Hash[:], h.Sum(nil)) != 1 {
                    fmt.Printf("%s %s : hash verification failed\n", color.RedString("✖ detach"), rel)
                    os.Exit(2)
                }

                if v.Size != uint64(size) {
                    panic(fmt.Errorf("%s : file size is different. did you hit the hash collision jackpot?", rel))
                }

                fmt.Println(color.GreenString("✔ detach"), v.Name)
            }

            if len(args) > 1 {
                os.Exit(2)
            }

        },
    };
    verifyCmd.Flags().StringVarP(&argIdentity,  "identity",  "i",  "", "verify document is signed by an identity")
    verifyCmd.Flags().StringVarP(&argParent,    "parent", "p",  "", "verify document is signed in sequence to another document")
    rootCmd.AddCommand(verifyCmd);


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
