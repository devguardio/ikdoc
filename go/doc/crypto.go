package doc


import (
    "github.com/devguardio/identity/go"
    "golang.org/x/crypto/hkdf"
    "crypto/sha256"
    "crypto/rand"
    "io"
    "golang.org/x/crypto/chacha20poly1305"
    "fmt"
)

func Ratchet(doc []byte , chainkey []byte) (sk identity.Secret, ck identity.Secret, prk identity.Secret)  {

    prkb := hkdf.Extract(sha256.New, doc, chainkey)
    if len(prkb) != 32 { panic("expected hkdf.Extract(sha256) to return 32 bytes") }
    copy(prk[:], prkb);
    hkdf := hkdf.Expand(sha256.New, prk[:], []byte("ikdoc ratchet"))

    if _, err := io.ReadFull(hkdf, sk[:]); err != nil {
        panic(err)
    }
    if _, err := io.ReadFull(hkdf, ck[:]); err != nil {
        panic(err)
    }
    return
}

func ResumeRatchetFromString(secret string) (sk identity.Secret, ck identity.Secret, err error) {
    rk, err := identity.SecretFromString(secret)
    if err != nil { return sk, ck, err }
    hkdf := hkdf.Expand(sha256.New, rk[:], []byte("ikdoc ratchet"))
    if _, err := io.ReadFull(hkdf, sk[:]); err != nil {
        panic(err)
    }
    if _, err := io.ReadFull(hkdf, ck[:]); err != nil {
        panic(err)
    }
    return
}

func Seal(key []byte, serial uint64, msg []byte) ([]byte, error) {

    var nonce [12]byte
    binary.BigEndian.PutUint64(nonce[4:], serial)

    aead, err := chacha20poly1305.New(key[:])
    if err != nil { return nil, err }

    nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(msg)+aead.Overhead())
    _, err = rand.Read(nonce[:])
    if err != nil { return nil, err }

    return aead.Seal(nonce, nonce, msg, nil), nil
}

func Unseal(key []byte, serial uint64, msg []byte) ([]byte, error) {

    var nonce [12]byte
    binary.BigEndian.PutUint64(nonce[4:], serial)

    aead, err := chacha20poly1305.New(key[:])
    if err != nil { return nil, err }

    if len(msg) < aead.NonceSize() {
        return nil, fmt.Errorf("ciphertext too short")
	}

    nonce, ciphertext := msg[:aead.NonceSize()], msg[aead.NonceSize():]

    return aead.Open(nil, nonce, ciphertext, nil)
}

/*
import (
    "golang.org/x/crypto/chacha20poly1305"
    "encoding/binary"
)

func decrypt(k [32]byte, serial uint64, ciphertext []byte) ([]byte, error) {

	c, err := chacha20poly1305.New(k[:])
	if err != nil { return nil, err }

    var nonce [12]byte
    binary.LittleEndian.PutUint64(nonce[4:], serial)

}
*/
