package identity


import (
    "io/ioutil"
    "os"
    "errors"
    "log"
)


type VaultI interface {
    Init(interactive bool) error
    Identity()  (*Identity, error)
    XPublic()   (*XPublic, error)
    RSAPublic() (*RSAPublic, error)
    MakeCA()    ([]byte, error)
    MakeRSACA() ([]byte, error)

    MakeCert    (p *Identity,  names []string) ([]byte, error)
    MakeRSACert (p *RSAPublic, names []string) ([]byte, error)


    // will error for HSM, so use the other methods
    ExportSecret()    (*Secret,     error)
    ExportRSASecret() (*RSASecret,  error)
}

type FileVault struct {
}


func (self *FileVault) Init(interactive bool)  error {
    path, err := os.UserHomeDir()
    if err != nil {
        path = "/root/"
    }

    var path2 = path + "/.devguard/ed25519.secret"
    if _, err := os.Stat(path2); !os.IsNotExist(err) {
        log.Println("NOT overriding existing ", path2)
    } else {

        secret, err := CreateSecret()
        if err != nil { return err}

        err = ioutil.WriteFile(path2, []byte(secret.ToString()), 0400)
        if err != nil { return err}
    }


    path2 = path + "/.devguard/rsa.secret"
    if _, err := os.Stat(path2); !os.IsNotExist(err) {
        log.Println("NOT overriding existing ", path2)
    } else {

        secret, err := CreateRSASecret(3072)
        if err != nil { return err}

        err = ioutil.WriteFile(path2, []byte(secret.ToString()), 0400)
        if err != nil { return err}
    }


    return nil
}

func (self *FileVault) Secret()  (*Secret, error) {
    path, err := os.UserHomeDir()
    if err != nil {
        path = "/root/"
    }
    path += "/.devguard/ed25519.secret"

    if _, err := os.Stat(path); os.IsNotExist(err) {
        return nil, errors.New("missing ~/.devguard/ed25519.secret\n=> run 'ik init' to create a new identity")
    }

    content, err := ioutil.ReadFile(path)
    if err != nil { return nil, err}

    s, err := SecretFromString(string(content))
    if err != nil { return nil, err}

    return s, nil
}

func (self *FileVault) RSASecret()  (*RSASecret, error) {
    path, err := os.UserHomeDir()
    if err != nil {
        path = "/root/"
    }
    path += "/.devguard/rsa.secret"

    if _, err := os.Stat(path); os.IsNotExist(err) {
        return nil, errors.New("missing ~/.devguard/rsa.secret\n=> run 'ik init' to create a new identity")
    }

    content, err := ioutil.ReadFile(path)
    if err != nil { return nil, err}

    s, err := RSASecretFromString(string(content))
    if err != nil { return nil, err}

    return s, nil
}

func (self *FileVault) Identity()  (*Identity, error) {
    secret, err := self.Secret()
    if err != nil { return nil, err}
    return secret.Identity(), nil
}

func (self *FileVault) XPublic()  (*XPublic, error) {
    secret, err := self.Secret()
    if err != nil { return nil, err}
    return secret.XSecret().XPublic(), nil
}

func (self *FileVault) RSAPublic()  (*RSAPublic, error) {
    secret, err := self.RSASecret()
    if err != nil { return nil, err}
    return secret.RSAPublic(), nil
}

func (self *FileVault) ExportSecret() (*Secret, error) {
    return self.Secret()
}

func (self *FileVault) ExportRSASecret() (*RSASecret, error) {
    return self.RSASecret()
}

func (self *FileVault) MakeCA() ([]byte, error) {
    p, err := self.Secret()
    if err != nil { return nil, err }
    return makeCA(p.ToGo())
}

func (self *FileVault) MakeRSACA() ([]byte, error) {
    p, err := self.RSASecret()
    if err != nil { return nil, err }
    return makeCA(p.ToGo())
}

func (self *FileVault) MakeCert(p *Identity, names []string) ([]byte, error) {
    k, err := self.Secret()
    if err != nil { return nil, err }
    return makeCert(p.ToGo(), k.ToGo(), names)
}

func (self *FileVault) MakeRSACert(p *RSAPublic, names []string) ([]byte, error) {
    k, err := self.RSASecret()
    if err != nil { return nil, err }
    return makeCert(p.ToGo(), k.ToGo(), names)
}


func Vault() VaultI {
    var self = &FileVault{}
    return self
}


