package doc

import (
    "net/http"
    "io"
    "github.com/devguardio/identity/go"
    iktls "github.com/devguardio/identity/go/tls"
    "fmt"
    "os"
    "io/ioutil"
    "bytes"
    "crypto/sha256"
    "path/filepath"
    "github.com/fatih/color"
    "strings"
    "crypto/subtle"
    "time"
)


func Sync(document string, url string) (bool, error) {

    var hasupdatedsomething = false

    for ;; {

        docbytes, err := ioutil.ReadFile(document)
        if err != nil { return hasupdatedsomething, fmt.Errorf("%s : %w", document, err) }

        parent, err := ReadDocument(bytes.NewReader(docbytes))
        if err != nil { return hasupdatedsomething, (fmt.Errorf("%s : %w", document, err)) }

        parenthash := sha256.Sum256(docbytes);

        chaindir := filepath.Join(filepath.Dir(document), ".ikchain");
        os.MkdirAll(chaindir, os.ModePerm)

        fn := filepath.Join(chaindir, fmt.Sprintf("%x.next", parenthash))
        nexthash, err := ioutil.ReadFile(fn)
        if err != nil || len(nexthash) == 0 {
            if url != ""  {
                nurl := url + "/.ikchain/" + fmt.Sprintf("%x.next", parenthash)
                nexthash, err = httpdownload(nurl)
                if err != nil { return hasupdatedsomething,(fmt.Errorf("%s : %v\n", nurl , err)) }
                if len(nexthash) != 0 {
                    err = ioutil.WriteFile(fn, nexthash, 0644)
                    if err != nil { return hasupdatedsomething, (fmt.Errorf("%s : %v\n", fn, err)) }
                }
            }
        }


        if len(nexthash) == 0 {

            fmt.Printf("%s %x\n", color.GreenString("✔ latest"), parenthash)

            if hasupdatedsomething && url != "" {
                for _,v := range parent.Detached {
                    if strings.Contains(v.Name, "/") {
                        continue
                    }
                    fn := filepath.Join(filepath.Dir(document), v.Name)
                    nurl := url + v.Name
                    nb , err := httpdownload(nurl)
                    if err != nil { return hasupdatedsomething, (fmt.Errorf("%s : %v\n", nurl, err)) }

                    h := sha256.New()
                    h.Write([]byte(v.Name))
                    h.Write(nb)
                    if subtle.ConstantTimeCompare(v.Hash[:], h.Sum(nil)) != 1 {
                        return false, fmt.Errorf("%s : hash verification failed\n", v.Name)
                    }

                    if nb != nil {
                        err = ioutil.WriteFile(fn, nb, 0644)
                        if err != nil { return hasupdatedsomething, (fmt.Errorf("%s : %v\n", fn, err)) }
                    }
                }
            }

            err = parent.VerifyDetached(filepath.Dir(document), true, DocumentOptDump{Writer: os.Stdout})
            if err != nil { return hasupdatedsomething, err }
            return hasupdatedsomething, nil
        }

        fn = filepath.Join(chaindir, strings.TrimSpace(string(nexthash)))
        nextbytes, err := ioutil.ReadFile(fn)
        if err != nil && url != "" {
            nextbytes, err = httpdownload(url + "/.ikchain/" + strings.TrimSpace(string(nexthash)))
            if err != nil { return hasupdatedsomething, (fmt.Errorf("%s : %v\n", fn, err)) }
            if len(nexthash) != 0 {
                err = ioutil.WriteFile(fn, nextbytes, 0644)
                if err != nil { return hasupdatedsomething, (fmt.Errorf("%s : %v\n", fn, err)) }
            }
        }
        if err != nil {
            return hasupdatedsomething, (fmt.Errorf("%s : %w", fn, err))
        }

        _ , err = parent.VerifySuccessor(nextbytes, DocumentOptDump{Writer: os.Stdout})
        if err != nil {
            return hasupdatedsomething, err
        }

        err = ioutil.WriteFile(document, nextbytes, 0644);
        if err != nil { return hasupdatedsomething, (fmt.Errorf("%s : %w", document, err))}

        hasupdatedsomething = true
    }
}

func httpdownload(url string) ([]byte, error) {

    vault := identity.Vault()
    tls, err := iktls.NewTlsClient(vault)
    if err != nil { return nil, err }

    //TODO
    tls.InsecureSkipVerify = true

    client := &http.Client{Transport: &http.Transport{ TLSClientConfig: tls }}
    client.Timeout = time.Minute


    req, err := http.NewRequest("GET", url, nil)
    if err != nil { return nil, err }

    resp, err := client.Do(req)
    if err != nil { return nil, err }
    defer resp.Body.Close();

    if resp.StatusCode == 200 {
        return ioutil.ReadAll(io.LimitReader(resp.Body, 20000000))
    } else if resp.StatusCode == 404 {
        return nil, nil
    }

    return nil, fmt.Errorf("%s", resp.Status)

}
