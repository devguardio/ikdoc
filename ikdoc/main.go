package main

import (
    "github.com/spf13/cobra"
    "github.com/devguardio/identity/go"
    "github.com/devguardio/ikdoc"
    "log"
    "fmt"
    "os"
    "io/ioutil"
    "github.com/fatih/color"
    "path/filepath"
    "strings"
    "crypto/sha256"
    "crypto/rand"
    "time"
    badrand "math/rand"
    "context"
)

func main() {
    log.SetFlags(log.Lshortfile);
    badrand.Seed(time.Now().UnixNano())


    var domain = ""
    var rootCmd = &cobra.Command{
        Use:        "doc",
        Short:      "signed documents",
    }
    rootCmd.PersistentFlags().StringVarP(&domain, "domain", "u", "", "use vault in separate user specific domain")

    rootCmd.AddCommand(&cobra.Command{
        Use:        "serve [path/to/.ikchain]",
        Short:      "serve ikchain over http",
        Args:       cobra.MinimumNArgs(1),
        Run: func(cmd *cobra.Command, args []string) {
            Serve(args[0])
        },
    })

    rootCmd.AddCommand(&cobra.Command{
        Use:        "dump <filename>",
        Short:      "dump ikdoc as text repr",
        Args:       cobra.MinimumNArgs(1),
        Run: func(cmd *cobra.Command, args []string) {

            f, err := ioutil.ReadFile(args[0])
            if err != nil { panic(fmt.Errorf("%s : %w", args[0], err)) }

            if !strings.HasSuffix(args[0], ".ikdoc") {
                args[0] += ".ikdoc"
            }
            fn := args[0][:len(args[0])-len(".ikdoc")] + ".iksecret"
            b, err := ioutil.ReadFile(fn)
            if err == nil {
                sealkey, _ , err := ikdoc.ResumeRatchetFromString(string(b))
                if err != nil { panic(fmt.Errorf("%s : %w", fn, err)) }
                _ , err = ikdoc.ParseDocument(f, ikdoc.OptUnsealKey(sealkey), ikdoc.OptDump{Writer: os.Stdout})
                if err != nil { panic(fmt.Errorf("%s : %w", args[0], err)) }
            } else {
                _ , err = ikdoc.ParseDocument(f, ikdoc.OptDump{Writer: os.Stdout})
                if err != nil { panic(fmt.Errorf("%s : %w", args[0], err)) }
            }
        },
    })

    rootCmd.AddCommand(&cobra.Command{
        Use:        "cat <filename> <key>",
        Short:      "dump ikdoc attachment for key",
        Args:       cobra.MinimumNArgs(2),
        Run: func(cmd *cobra.Command, args []string) {

            f, err := ioutil.ReadFile(args[0])
            if err != nil { panic(fmt.Errorf("%s : %w", args[0], err)) }

            if !strings.HasSuffix(args[0], ".ikdoc") {
                args[0] += ".ikdoc"
            }
            fn := args[0][:len(args[0])-len(".ikdoc")] + ".iksecret"
            b, err := ioutil.ReadFile(fn)

            var doc *ikdoc.Document
            if err == nil {
                sealkey, _ , err := ikdoc.ResumeRatchetFromString(string(b))
                if err != nil { panic(fmt.Errorf("%s : %w", fn, err)) }
                doc , err = ikdoc.ParseDocument(f, ikdoc.OptUnsealKey(sealkey))
                if err != nil { panic(fmt.Errorf("%s : %w", args[0], err)) }
            } else {
                doc , err = ikdoc.ParseDocument(f, ikdoc.OptDump{Writer: os.Stdout})
                if err != nil { panic(fmt.Errorf("%s : %w", args[0], err)) }
            }

            for _, v := range doc.Attached {
                if v.Name == args[1] {
                    os.Stdout.Write(v.Message);
                    return
                }
            }

            if doc.Sealed != nil {
                for _, v := range doc.Sealed.Attached {
                    if v.Name == args[1] {
                        os.Stdout.Write(v.Message);
                        return
                    }
                }
            }
            os.Exit(1)
        },
    })

    var argWatch bool
    syncCmd := &cobra.Command{
        Use:    "sync <ikdoc> [url]",
        Short:  "sync ikdoc to a local or remote chain and verify",
        Args:   cobra.MinimumNArgs(2),
        Run: func(cmd *cobra.Command, args []string) {

            var ctx   = context.Background()
            var vault = identity.Vault()

            var url = "";
            if len(args) > 1 { url = args[1] }

            if argWatch {
                 ikdoc.Wait(ctx, vault, args[0], url)
            } else {
                _ ,err := ikdoc.Sync(ctx, vault, args[0], url, argWatch)
                if err != nil { panic(err) }
            }
        },
    }
    syncCmd.Flags().BoolVarP(&argWatch, "watch",    "w",  false, "watch for changes")
    rootCmd.AddCommand(syncCmd);


    var argAnon     bool
    var argChain    bool
    var argRekey    bool

    var argAttached = make(map[string]string)
    var argPlain    = make(map[string]string)

    var argEmbed = make(map[string]string)
    var argSeal  = make(map[string]string)

    var argUnnamed  []string
    var argDetached = make(map[string]string)

    var argRemove   []string

    var argParent   string
    var argUrl      []string

    var common = func(editParent *ikdoc.Document, args []string) {

        var vault = identity.Vault()
        if domain != "" { vault = vault.Domain(domain) }

        id, err:= vault.Identity()
        if err != nil { panic(err) }

        var doc    *ikdoc.Document = &ikdoc.Document {}

        var parentbytes []byte
        if argParent != "" {
            parentbytes, err = ioutil.ReadFile(argParent)
            if err != nil { panic(fmt.Errorf("%s : %w", argParent, err)) }

            parent, err := ikdoc.ParseDocument(parentbytes)
            if err != nil { panic(fmt.Errorf("%s : %w", argParent, err)) }

            doc = parent.NewSequence();
        }

        var sealkey, chainkey, ratchetkey identity.Secret
        var hasRatchet = false

        if len(argAttached) > 0 || len(argSeal) > 0 || (editParent != nil && editParent.Sealed != nil) {
            if len(parentbytes) == 0  {
                _, err := rand.Read(chainkey[:])
                if err != nil { panic(err) }
            } else {
                fn := argParent[:len(argParent)-len(".ikdoc")] + ".iksecret"
                b , err := ioutil.ReadFile(fn)
                if err != nil { panic(fmt.Errorf("%s : %w", fn, err)) }
                _, chainkey , err = ikdoc.ResumeRatchetFromString(string(b))
                if err != nil { panic(fmt.Errorf("%s : %w", fn, err)) }
            }

            sealkey, _ , ratchetkey = ikdoc.Ratchet(parentbytes, chainkey[:])
            hasRatchet = true
            doc.Sealed = ikdoc.NewSealedDocument(sealkey[:])

            doc.Sealed.Salt = make([]byte, 8)
            _, err := rand.Read(doc.Sealed.Salt)
            if err != nil { panic(err) }

            for k,v := range argAttached{
                err = doc.Sealed.WithAttached([]byte(v), k)
                if err != nil { panic(err) }
            }
            for k,v := range argSeal {
                v, err := os.ReadFile(v)
                if err != nil { panic(err) }

                err = doc.Sealed.WithAttached(v, k)
                if err != nil { panic(err) }
            }
        }

        // this just avoids chain collission
        if argParent == "" && doc.Sealed == nil {
            doc.Salt = make([]byte, 8)
            _, err := rand.Read(doc.Salt)
            if err != nil { panic(err) }
        }

        if editParent != nil {
            yeet := make(map[string]bool)
            for _,v := range argRemove {
                yeet[v] = true
            }

            if editParent.Sealed != nil {
                for _,v := range editParent.Sealed.Attached {
                    if yeet[v.Name] { continue }

                    err = doc.Sealed.WithAttached(v.Message, v.Name)
                    if err != nil { panic(err) }
                }
            }

            for _,v := range editParent.Attached {
                if yeet[v.Name] { continue }

                err = doc.WithAttached(v.Message, v.Name)
                if err != nil { panic(err) }
            }

            // yeet empty sealed doc
            if doc.Sealed != nil && len(doc.Sealed.Attached) == 0 && len(doc.Sealed.Detached) == 0 {
                doc.Sealed = nil
            }
        }




        for k,v := range argPlain{
            err = doc.WithAttached([]byte(v), k)
            if err != nil { panic(err) }
        }

        for k,v := range argEmbed {
            v, err := os.ReadFile(v)
            if err != nil { panic(err) }

            err = doc.WithAttached(v, k)
            if err != nil { panic(err) }
        }

        for k,v := range argDetached {
            f, err := os.Open(v)
            if err != nil { panic(err) }
            defer f.Close();

            err = doc.WithDetached(f, k)
            if err != nil { panic(err) }
        }
        for _, n := range argUnnamed {
            f, err := os.Open(n)
            if err != nil { panic(err) }
            defer f.Close();

            err = doc.WithDetached(f, "")
            if err != nil { panic(err) }
        }

        for _,v := range argUrl {
            err = doc.WithBaseUrl(v)
            if err != nil { panic(err) }
        }

        if !argAnon {
            doc.Anchors = []identity.Identity{*id}
        }

        if !strings.HasSuffix(args[0], ".ikdoc") {
            args[0] += ".ikdoc"
        }

        b, err := doc.EncodeAndSign(vault);
        if err != nil { panic(fmt.Errorf("%s : %w", args[0], err)) }


        if argChain {

            chaindir := filepath.Join(filepath.Dir(args[0]), ".ikchain");
            err = os.MkdirAll(chaindir, os.ModePerm)
            if err != nil { panic(fmt.Errorf("%s : %w", chaindir, err)) }

            hash := sha256.Sum256(b)
            fn := filepath.Join(chaindir, fmt.Sprintf("%x", hash));
            err = ioutil.WriteFile(fn, b, 0644)
            if err != nil { panic(fmt.Errorf("%s : %w", fn, err)) }


            if parentbytes != nil {
                parenthash := sha256.Sum256(parentbytes)

                fn := filepath.Join(chaindir, fmt.Sprintf("%x", parenthash));
                err = ioutil.WriteFile(fn, parentbytes, 0644)
                if err != nil { panic(fmt.Errorf("%s : %w", fn, err)) }

                fn = filepath.Join(chaindir, fmt.Sprintf("%x.next", parenthash));
                f, err := os.OpenFile(fn, os.O_RDWR | os.O_CREATE | os.O_EXCL, 0644)
                if err != nil { panic(fmt.Errorf("%s : %w", fn, err)) }
                defer f.Close();

                _, err = f.Write([]byte(fmt.Sprintf("%x\n", hash)))
                if err != nil { panic(err) }
            }
        }

        f, err := os.OpenFile(args[0], os.O_RDWR | os.O_CREATE | os.O_EXCL, 0644)
        if err != nil {
            if argChain && argParent == args[0] {
                f, err = os.Create(args[0])
            }
        }
        if err != nil {
            panic(fmt.Errorf("%s : %w", args[0], err))
        }
        defer f.Close();

        _, err = f.Write(b)
        if err != nil { panic(err) }

        if hasRatchet {
            fn := args[0][:len(args[0])-len(".ikdoc")] + ".iksecret"
            err = ioutil.WriteFile(fn, []byte(ratchetkey.ToString()), 0644)
            if err != nil { panic(fmt.Errorf("%s : %w", fn, err)) }
        }
    }

    signCmd := &cobra.Command{
        Use:        "sign <outfile> -m hello=world -e file.txt",
        Short:      "sign files and pack into a <filename>.ikdoc",
        Args:       cobra.MinimumNArgs(1),
        Run: func(cmd *cobra.Command, args []string) {
            common(nil, args)
        },
    }
    signCmd.Flags().StringToStringVarP(&argPlain,   "cleartext","M",  map[string]string{}, "attach a cleartext signed key value message")
    signCmd.Flags().StringToStringVarP(&argAttached,"message",  "m",  map[string]string{}, "attach a sealed signed key value message")

    signCmd.Flags().StringToStringVarP(&argEmbed,   "embed",    "E",  map[string]string{}, "embed a cleartext signed file")
    signCmd.Flags().StringToStringVarP(&argSeal,    "seal",     "e",  map[string]string{}, "embed a sealed signed file")

    signCmd.Flags().StringToStringVarP(&argDetached,"detached", "d",  map[string]string{}, "reference detached file")
    signCmd.Flags().StringArrayVarP(&argUnnamed,    "unnamed",  "D",  []string{}, "reference unnamed detached file")

    signCmd.Flags().BoolVarP(&argAnon,              "anon",     "a",  false, "do not reveal signee (also prevents sequencing)")
    signCmd.Flags().StringVarP(&argParent,          "parent",   "p",  "", "document follows a previous document in a sequence")
    signCmd.Flags().StringArrayVarP(&argUrl,        "base",     "b",  []string{}, "ikd sync base url")
    signCmd.Flags().BoolVarP(&argChain,             "chain",    "c",  false, "record history in .ikchain for sync")
    signCmd.Flags().BoolVarP(&argRekey,             "rekey",    "k",  false, "mix secret encryption key for next message")

    rootCmd.AddCommand(signCmd);

    editCmd := &cobra.Command{
        Use:        "edit <outfile.ikdoc> -m hello=world -e file.txt",
        Short:      "append to existing ikdoc (requires ikchain)",
        Args:       cobra.MinimumNArgs(1),
        Run: func(cmd *cobra.Command, args []string) {

            argParent = args[0]
            argChain  = true


            f, err := ioutil.ReadFile(args[0])
            if err != nil { panic(fmt.Errorf("%s : %w", args[0], err)) }

            if !strings.HasSuffix(args[0], ".ikdoc") {
                args[0] += ".ikdoc"
            }

            var hassecret = true
            fn := args[0][:len(args[0])-len(".ikdoc")] + ".iksecret"
            b, err := ioutil.ReadFile(fn)

            var doc *ikdoc.Document
            if err == nil {
                hassecret = true
                sealkey, _ , err := ikdoc.ResumeRatchetFromString(string(b))
                if err != nil { panic(fmt.Errorf("%s : %w", fn, err)) }
                doc , err = ikdoc.ParseDocument(f, ikdoc.OptUnsealKey(sealkey))
                if err != nil { panic(fmt.Errorf("%s : %w", args[0], err)) }
            } else {
                hassecret = false
                doc , err = ikdoc.ParseDocument(f)
                if err != nil { panic(fmt.Errorf("%s : %w", args[0], err)) }
            }

            if doc.Sealed != nil && !hassecret {
                _, err := ioutil.ReadFile(fn)
                if err != nil { panic(fmt.Errorf("%s : %w", fn, err)) }
            }

            common(doc, args)
        },
    }

    editCmd.Flags().StringToStringVarP(&argPlain,   "cleartext","M",  map[string]string{}, "attach a cleartext signed key value message")
    editCmd.Flags().StringToStringVarP(&argAttached,"message",  "m",  map[string]string{}, "attach a sealed signed key value message")

    editCmd.Flags().StringToStringVarP(&argEmbed,   "embed",    "E",  map[string]string{}, "embed a cleartext signed file")
    editCmd.Flags().StringToStringVarP(&argSeal,    "seal",     "e",  map[string]string{}, "embed a sealed signed file")

    editCmd.Flags().StringToStringVarP(&argDetached,"detached", "d",  map[string]string{}, "reference detached file")
    editCmd.Flags().StringArrayVarP(&argUnnamed,    "unnamed",  "D",  []string{}, "reference unnamed detached file")

    editCmd.Flags().BoolVarP(&argAnon,              "anon",     "a",  false, "do not reveal signee (also prevents sequencing)")
    editCmd.Flags().StringArrayVarP(&argUrl,        "base",     "b",  []string{}, "ikd sync base url")
    editCmd.Flags().BoolVarP(&argRekey,             "rekey",    "k",  false, "mix secret encryption key for next message")

    editCmd.Flags().StringArrayVarP(&argRemove,     "remove",   "r",  []string{}, "remove any key before adding anything")

    rootCmd.AddCommand(editCmd);


    var argIdentity string
    verifyCmd := &cobra.Command{
        Use:        "verify <filename> [ -i <identity> |  -p <parent> ]",
        Short:      "verify an ikdoc is signed by an identity or sequence",
        Args:       cobra.MinimumNArgs(1),
        Run: func(cmd *cobra.Command, args []string) {

            var doc *ikdoc.Document

            if argParent != "" {

                f, err := ioutil.ReadFile(argParent)
                if err != nil { panic(fmt.Errorf("%s : %w", args[0], err)) }

                precedent, err := ikdoc.ParseDocument(f)
                if err != nil { panic(fmt.Errorf("%s : %w", argParent, err)) }

                b, err := ioutil.ReadFile(args[0])
                if err != nil { panic(fmt.Errorf("%s : %w", args[0], err)) }

                doc, err = precedent.VerifySuccessor(b, ikdoc.OptDump{Writer: os.Stdout})
                if err != nil {
                    fmt.Printf("%s : %v\n", args[0], err);
                    os.Exit(2)
                }

            } else if argIdentity != "" {

                id, err := identity.IdentityFromString(argIdentity)
                if err != nil { panic(fmt.Errorf("%s : %w", argIdentity, err)) }

                b, err := ioutil.ReadFile(args[0])
                if err != nil { panic(fmt.Errorf("%s : %w", args[0], err)) }

                doc, err = ikdoc.ParseDocument(b)
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


            err := doc.VerifyDetached(filepath.Dir(args[0]), true, ikdoc.OptDump{Writer: os.Stdout})
            if err != nil {
                panic(err)
            }

        },
    };
    verifyCmd.Flags().StringVarP(&argIdentity,  "identity",  "i",  "", "verify document is signed by an identity")
    verifyCmd.Flags().StringVarP(&argParent,    "parent", "p",  "", "verify document is signed in sequence to another document")
    rootCmd.AddCommand(verifyCmd);

    if err := rootCmd.Execute(); err != nil {
        os.Exit(1);
    }
}


