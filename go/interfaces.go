package identity

type Signer interface {
    Sign        (subject string, message []byte) (*Signature, error)
    Identity()  (*Identity, error)
}
