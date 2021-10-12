package main

import (
    "github.com/spf13/cobra"
    "github.com/devguardio/identity/go"
    "log"
    "fmt"
    "os"
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
        Use:    "identity",
        Aliases:  []string{"id"},
        Short:  "print my identity",
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
        Short:  "emit a pki ca cert",
        Run: func(cmd *cobra.Command, args []string) {
            if usersa {
                pem, err := identity.Vault().MakeRSACA()
                if err != nil { panic(err) }
                os.Stdout.Write([]byte(pem))
            } else {
                pem, err := identity.Vault().MakeCA()
                if err != nil { panic(err) }
                os.Stdout.Write([]byte(pem))
            }
        },
    });

    rootCmd.AddCommand(&cobra.Command{
        Use:    "tls name1 [name2 ..]",
        Short:  "create a new signed certificate bundle",
        Args:   cobra.MinimumNArgs(1),
        Run: func(cmd *cobra.Command, args []string) {
            if usersa {

                key, err := identity.CreateRSASecret(2048);
                if err != nil { panic(err) }

                pem, err := identity.Vault().MakeRSACert(key.RSAPublic(), args)
                if err != nil { panic(err) }
                os.Stdout.Write([]byte(pem))

                pem, err = key.ToPem()
                if err != nil { panic(err) }
                os.Stdout.Write([]byte(pem))

            } else {

                key, err := identity.CreateSecret();
                if err != nil { panic(err) }

                pem, err := identity.Vault().MakeCert(key.Identity(), args)
                if err != nil { panic(err) }
                os.Stdout.Write([]byte(pem))

                pem, err = key.ToPem()
                if err != nil { panic(err) }
                os.Stdout.Write([]byte(pem))
            }
        },
    });

    if err := rootCmd.Execute(); err != nil {
        os.Exit(1);
    }
}
