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
    "os/exec"
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
        Args:   cobra.MinimumNArgs(1),
        Run: func(cmd *cobra.Command, args []string) {

            var ctx   = context.Background()
            var vault = identity.Vault()

            if argWatch {
                ikdoc.Wait(ctx, vault, args[0], args[1:])
            } else {
                _ ,err := ikdoc.Sync(ctx, vault, args[0], args[1:], argWatch)
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

    var argParent   string
    var argUrl      []string

    signCmd := &cobra.Command{
        Use:        "sign <outfile> --message hello=world --seal file.txt",
        Short:      "sign files and pack into a <filename>.ikdoc",
        Args:       cobra.MinimumNArgs(1),
        Run: func(cmd *cobra.Command, args []string) {
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

            if len(argAttached) > 0 || len(argSeal) > 0 {
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
        },
    }
    signCmd.Flags().StringToStringVar(&argPlain,   "plain", map[string]string{}, "attach a plain signed key value message")
    signCmd.Flags().StringToStringVar(&argAttached,"message",   map[string]string{}, "attach a sealed signed key value message")

    signCmd.Flags().StringToStringVar(&argEmbed,   "embed",     map[string]string{}, "embed a plain signed file")
    signCmd.Flags().StringToStringVar(&argSeal,    "seal",      map[string]string{}, "embed a sealed signed file")

    signCmd.Flags().StringToStringVar(&argDetached,"detached",  map[string]string{}, "reference detached file")
    signCmd.Flags().StringArrayVar(&argUnnamed,    "unnamed",   []string{}, "reference unnamed detached file")

    signCmd.Flags().BoolVar(&argAnon,              "anon",      false, "do not reveal signee (also prevents sequencing)")
    signCmd.Flags().StringVar(&argParent,          "parent",    "", "document follows a previous document in a sequence")
    signCmd.Flags().StringArrayVar(&argUrl,        "base",      []string{}, "ikd sync base url")
    signCmd.Flags().BoolVar(&argChain,             "chain",     false, "record history in .ikchain for sync")
    signCmd.Flags().BoolVar(&argRekey,             "rekey",     false, "mix secret encryption key for next message")

    rootCmd.AddCommand(signCmd);





    var argMessage  = make(map[string]string)
    var argRemove   []string
    var argClear    bool
    var argExtern   []string

    editCmd := &cobra.Command{
        Use:        "edit <outfile.ikdoc> --remove hello --plain hello=world",
        Short:      "append to existing ikdoc (requires ikchain)",
        Args:       cobra.MinimumNArgs(1),
        Run: func(cmd *cobra.Command, args []string) {

            var vault = identity.Vault()
            if domain != "" { vault = vault.Domain(domain) }

            docbytes, err := ioutil.ReadFile(args[0])
            if err != nil { panic(fmt.Errorf("%s : %w", args[0], err)) }

            fn := ikdoc.RelatedFilePath(args[0], ".iksecret")
            secretbytes, _ := ioutil.ReadFile(fn)

            editor, err := ikdoc.Edit(docbytes, secretbytes)

            if argClear {
                editor.Clear();
            }

            for _,v := range argRemove {
                err := editor.Remove(v)
                if err != nil { panic(err) }
            }

            for k,v := range argPlain{
                err := editor.AppendPlaintextMessage(k, []byte(v))
                if err != nil { panic(err) }
            }

            for k,v := range argMessage{
                err := editor.AppendSealedMessage(k, []byte(v))
                if err != nil { panic(err) }
            }

            for k,v := range argSeal {
                v, err := os.ReadFile(v)
                if err != nil { panic(err) }

                err = editor.AppendSealedMessage(k, []byte(v))
                if err != nil { panic(err) }
            }

            for k,v := range argEmbed {
                v, err := os.ReadFile(v)
                if err != nil { panic(err) }

                err = editor.AppendPlaintextMessage(k, []byte(v))
                if err != nil { panic(err) }
            }

            for _,v := range argExtern {
                err = editor.Edit(v, func(msg []byte ) ([]byte, error) {

                    file, err := ioutil.TempFile("", "*-" + v)
                    if err != nil { return nil, err}
                    file.Write(msg)
                    defer os.Remove(file.Name())
                    defer file.Close()

                    exteditor := os.Getenv("EDITOR")
                    if exteditor == "" {
                        return nil, fmt.Errorf("EDITOR env var not set")
                    }

                    cmd := exec.Command(exteditor, file.Name())
                    cmd.Stdin = os.Stdin
                    cmd.Stdout = os.Stdout
                    err = cmd.Run()
                    if err != nil { return nil, err }

                    return os.ReadFile(file.Name())
                })
                if err != nil { panic(err) }
            }

            nudocbytes, secret, err := editor.EncodeAndSign(vault);
            if err != nil { panic(fmt.Errorf("%s : %w", args[0], err)) }


            // ikchain

            chaindir := filepath.Join(filepath.Dir(args[0]), ".ikchain");
            err = os.MkdirAll(chaindir, os.ModePerm)
            if err != nil { panic(fmt.Errorf("%s : %w", chaindir, err)) }

            hash := sha256.Sum256(nudocbytes)
            fn = filepath.Join(chaindir, fmt.Sprintf("%x", hash));
            err = ioutil.WriteFile(fn, nudocbytes, 0644)
            if err != nil { panic(fmt.Errorf("%s : %w", fn, err)) }


            parenthash := sha256.Sum256(docbytes)

            fn = filepath.Join(chaindir, fmt.Sprintf("%x", parenthash));
            err = ioutil.WriteFile(fn, docbytes, 0644)
            if err != nil { panic(fmt.Errorf("%s : %w", fn, err)) }

            fn = filepath.Join(chaindir, fmt.Sprintf("%x.next", parenthash));
            f, err := os.OpenFile(fn, os.O_RDWR | os.O_CREATE | os.O_EXCL, 0644)
            if err != nil { panic(fmt.Errorf("%s : %w", fn, err)) }
            defer f.Close();

            _, err = f.Write([]byte(fmt.Sprintf("%x\n", hash)))
            if err != nil { panic(err) }


            // write doc

            err = ioutil.WriteFile(args[0], nudocbytes, 0644)
            if err != nil {
                panic(fmt.Errorf("%s : %w", args[0], err))
            }

            if secret != nil {
                fn := ikdoc.RelatedFilePath(args[0], ".iksecret")
                err = ioutil.WriteFile(fn, []byte(secret.ToString()), 0644)
                if err != nil { panic(fmt.Errorf("%s : %w", fn, err)) }
            }
        },
    }


    editCmd.Flags().StringToStringVar(&argPlain,    "plain",    map[string]string{}, "attach a plain signed key value message")
    editCmd.Flags().StringToStringVar(&argMessage,  "message",  map[string]string{}, "attach a sealed signed key value message")

    editCmd.Flags().StringToStringVar(&argEmbed,    "embed",    map[string]string{}, "embed a plain signed file")
    editCmd.Flags().StringToStringVar(&argSeal,     "seal",     map[string]string{}, "embed a sealed signed file")

    editCmd.Flags().StringArrayVar  (&argRemove,    "remove",   []string{},  "remove any attachment with this key")
    editCmd.Flags().BoolVar         (&argClear,     "clear",    false,       "remove all values")

    editCmd.Flags().StringArrayVar  (&argExtern,      "extern",   []string{},  "open in external EDITOR")

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


