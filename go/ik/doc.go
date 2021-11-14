package main

import (
    "github.com/spf13/cobra"
    "github.com/devguardio/identity/go"
    "log"
    "fmt"
    "os"
    "io/ioutil"
    "github.com/fatih/color"
    "bytes"
    "path/filepath"
    "strings"
    "crypto/sha256"
    "io"
    "crypto/subtle"
)

func docCmd() *cobra.Command {
    log.SetFlags(log.Lshortfile);

    var rootCmd = &cobra.Command{
        Use:        "doc",
        Short:      "signed documents",
    }

    rootCmd.AddCommand(&cobra.Command{
        Use:        "dump <filename>",
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

                b, err := ioutil.ReadFile(args[0])
                if err != nil { panic(fmt.Errorf("%s : %w", args[0], err)) }

                doc, err = precedent.VerifySuccessor(b, identity.DocumentOptDump{Writer: os.Stdout})
                if err != nil {
                    fmt.Printf("%s : %v\n", args[0], err);
                    os.Exit(2)
                }

            } else if argIdentity != "" {

                id, err := identity.IdentityFromString(argIdentity)
                if err != nil { panic(fmt.Errorf("%s : %w", argIdentity, err)) }

                b, err := ioutil.ReadFile(args[0])
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

    return rootCmd
}
