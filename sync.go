package ikdoc

import (
    "net/http"
    "io"
    "github.com/devguardio/identity/go"
    iktls "github.com/devguardio/identity/go/tls"
    "fmt"
    "os"
    "io/ioutil"
    "crypto/sha256"
    "path/filepath"
    "github.com/fatih/color"
    "strings"
    "crypto/subtle"
    "time"
    badrand "math/rand"
    "log"
    "context"
)


func Wait (ctx context.Context, document string, url string) {

    for ;; {
        change, err := Sync(ctx, document, url, true)
        if err != nil {
            log.Println(err)
        }

        if change {
            return
        }

        select {
        case <-ctx.Done():
            return
        case <- time.After(5 * time.Second):
            continue
        }
    }

}

func Sync(ctx context.Context, document string, url string, watch bool) (bool, error) {

    var hasupdatedsomething = false

    for ;; {

        docbytes, err := ioutil.ReadFile(document)
        if err != nil { return hasupdatedsomething, fmt.Errorf("%s : %w", document, err) }

        parent, err := ParseDocument(docbytes)
        if err != nil { return hasupdatedsomething, (fmt.Errorf("%s : %w", document, err)) }

        parenthash := sha256.Sum256(docbytes);

        chaindir := filepath.Join(filepath.Dir(document), ".ikchain");
        os.MkdirAll(chaindir, os.ModePerm)

        fn := filepath.Join(chaindir, fmt.Sprintf("%x.next", parenthash))
        nexthash, err := ioutil.ReadFile(fn)
        if err != nil || len(nexthash) == 0 {
            if url != ""  {
                nurl := url + "/.ikchain/" + fmt.Sprintf("%x.next", parenthash)
                fmt.Println("☎ remote", nurl)
                nexthash, err = httpdownload(ctx, nurl, watch)
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
                    nb , err := httpdownload(ctx, nurl, false)
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

            err = parent.VerifyDetached(filepath.Dir(document), true, OptDump{Writer: os.Stdout})
            if err != nil { return hasupdatedsomething, err }
            return hasupdatedsomething, nil
        }

        fn = filepath.Join(chaindir, strings.TrimSpace(string(nexthash)))
        nextbytes, err := ioutil.ReadFile(fn)
        if err != nil && url != "" {
            nextbytes, err = httpdownload(ctx, url + "/.ikchain/" + strings.TrimSpace(string(nexthash)), false)
            if err != nil { return hasupdatedsomething, (fmt.Errorf("%s : %v\n", fn, err)) }
            if len(nexthash) != 0 {
                err = ioutil.WriteFile(fn, nextbytes, 0644)
                if err != nil { return hasupdatedsomething, (fmt.Errorf("%s : %v\n", fn, err)) }
            }
        }
        if err != nil {
            return hasupdatedsomething, (fmt.Errorf("%s : %w", fn, err))
        }

        _ , err = parent.VerifySuccessor(nextbytes, OptDump{Writer: os.Stdout})
        if err != nil {
            return hasupdatedsomething, err
        }

        err = ioutil.WriteFile(document, nextbytes, 0644);
        if err != nil { return hasupdatedsomething, (fmt.Errorf("%s : %w", document, err))}




        fn = RelatedFilePath(document, ".iksecret")
        b , err := ioutil.ReadFile(fn)
        if err == nil {
            _, chainkey , err := ResumeRatchetFromString(string(b))
            if err != nil { return hasupdatedsomething, fmt.Errorf("%s : %w", fn, err) }
            _ , _ , ratchetkey := Ratchet(docbytes, chainkey[:])
            err = ioutil.WriteFile(fn, []byte(ratchetkey.ToString()), 0644)
            if err != nil { return hasupdatedsomething, fmt.Errorf("%s : %w", fn, err) }
        }

        hasupdatedsomething = true

        fmt.Printf("%s %s\n", color.GreenString("✔ update"), nexthash)
    }
}

func httpdownload(ctx context.Context, url string, watch bool) ([]byte, error) {

    vault := identity.Vault()
    tls, err := iktls.NewTlsClient(vault)
    if err != nil { return nil, err }

    //TODO
    tls.InsecureSkipVerify = true

    client := &http.Client{Transport: &http.Transport{ TLSClientConfig: tls }}
    if watch {
        client.Timeout = 10 * time.Minute + (time.Second * time.Duration(badrand.Intn(10)))
    } else {
        client.Timeout = time.Minute
    }


    req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
    if err != nil { return nil, err }

    if watch {
        req.Header.Add("Wait", client.Timeout.String());
    }

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
