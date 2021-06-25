package identity


import (
    "testing"
)

func TestIdentityFromStringGarbage(t *testing.T) {
    _ , err :=  IdentityFromString("cDFIOBGBIVQAW2YVIWVLMV19203819028390182390128312312313QA");
    if err == nil {
        t.Errorf("parsing must not succeed");
    }
}

var secret_string string = "cCOMZM5Z2HHCSVE65EDABQYXZHFA4AFH7NCTFG2VJ6V5OX7OXI33PMUQ";
var identity_string string = "cDFXSA73D3H4MOM7HPVUYWUOABQI7D5ERUR7QXOQPJD2HOYYSJCIYFWY";

func TestSecret(t *testing.T) {
    sk, err := SecretFromString(secret_string);
    if err != nil {
        panic(err);
    }

    if sk.String() == secret_string {
        t.Errorf("leaking secrets");
    }

    if sk.ToString() != secret_string {
        t.Errorf("expected SecretFromString(s).AsString() == s")
    }
}

func TestEd25519(t *testing.T) {
    sk, err := SecretFromString(secret_string);
    if err != nil {
        panic(err);
    }

    id := sk.Identity();

    if id.String() != identity_string {
        t.Errorf("expected SecretFromString(s).Identity().String() == identity_string")
    }
}

func TestIdentity(t *testing.T) {
    sk, err := IdentityFromString(identity_string);
    if err != nil {
        panic(err);
    }

    if sk.String() != identity_string {
        t.Errorf("expected IdentityFromString(s).AsString() == s")
    }
}

