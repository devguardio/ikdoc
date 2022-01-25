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
    "context"
    "encoding/hex"
    log "github.com/sirupsen/logrus"
)


func Wait (ctx context.Context, vault identity.VaultI, document string, urls []string) {

    for ;; {
        change, err := Sync(ctx, vault, document, urls, true)
        if err != nil {
            log.Error(fmt.Errorf("ikdoc waiting for %s : %w ", document, err))
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




// TODO this is dangerous because it might overwrite arbitrary local files
func SyncDetachments(ctx context.Context, vault identity.VaultI, document string, urls []string) (error) {

    docbytes, err := ioutil.ReadFile(document)
    if err != nil { return fmt.Errorf("%s : %w", document, err) }

    parent, err := ParseDocument(docbytes)
    if err != nil { return (fmt.Errorf("%s : %w", document, err)) }

    urls = append(urls, parent.BaseUrl...)

    for _,v := range parent.Detached {
        if strings.Contains(v.Name, "/") {
            continue
        }
        fn := filepath.Join(filepath.Dir(document), v.Name)

        nb , _ := httpdownload(ctx, vault, urls, v.Name, nil, false)
        if nb != nil {
            h := sha256.New()
            h.Write([]byte(v.Name))
            h.Write(nb)
            if subtle.ConstantTimeCompare(v.Hash[:], h.Sum(nil)) != 1 {
                return fmt.Errorf("%s : hash verification failed\n", v.Name)
            }

            if nb != nil {
                err = ioutil.WriteFile(fn, nb, 0644)
                if err != nil { return fmt.Errorf("%s : %v\n", fn, err) }
            }
        }
    }

    err = parent.VerifyDetached(filepath.Dir(document), true, OptDump{Writer: os.Stdout})
    if err != nil { return  err }
    return  nil
}


func Sync(ctx context.Context, vault identity.VaultI, document string, urls []string, watch bool) (bool, error) {

    var hasupdatedsomething = false

    for ;; {

        // read current checked out document

        docbytes, err := ioutil.ReadFile(document)
        if err != nil { return hasupdatedsomething, fmt.Errorf("%s : %w", document, err) }

        parent, err := ParseDocument(docbytes)
        if err != nil { return hasupdatedsomething, (fmt.Errorf("%s : %w", document, err)) }

        parenthash := sha256.Sum256(docbytes);

        chaindir := filepath.Join(filepath.Dir(document), ".ikchain");
        os.MkdirAll(chaindir, os.ModePerm)

        urls := append(urls, parent.BaseUrl...)

        // try to get a nexthash from local .ikchain

        fn := filepath.Join(chaindir, fmt.Sprintf("%x.next", parenthash))
        nexthash, err := ioutil.ReadFile(fn)
        if err != nil || len(nexthash) == 0 {


            // otherwise try to get a nexthash from a sync
            var path = ".ikchain/" + fmt.Sprintf("%x.next", parenthash)
            nexthash, err = httpdownload(ctx, vault, urls, path, nil, watch && !hasupdatedsomething)
            if err != nil { return hasupdatedsomething, err }
        }

        // no nexthash. we're done
        if len(nexthash) == 0 {
            log.Printf("[ikdoc] %s %x\n", color.GreenString("✔ latest"), parenthash)

            if hasupdatedsomething && len(urls) != 0 {
                err := SyncDetachments(ctx, vault, document, urls)
                if err != nil { return hasupdatedsomething, err }
            }

            return hasupdatedsomething, nil
        }

        // try to get the object for nexthash from local .ikchain
        fn = filepath.Join(chaindir, strings.TrimSpace(string(nexthash)))
        log.Println("[ikdoc] next is", fn);
        nextbytes, err := ioutil.ReadFile(fn)
        if err != nil && len(urls) != 0 {

            nexthash := strings.TrimSpace(string(nexthash))
            var decoded []byte
            decoded, err = hex.DecodeString(nexthash)
            if err != nil {
                return hasupdatedsomething, err
            }


            // otherwise download it
            nextbytes, err = httpdownload(ctx, vault, urls, ".ikchain/" + nexthash, decoded, false)
        }
        if err != nil {
            return hasupdatedsomething, (fmt.Errorf("%s : %w", fn, err))
        }


        // verify the next object is a successor
        _ , err = parent.VerifySuccessor(nextbytes, OptDump{Writer: os.Stdout})
        if err != nil {
            return hasupdatedsomething, err
        }


        // SAFE FROM HERE


        fn = RelatedFilePath(document, ".iksecret")
        b , err := ioutil.ReadFile(fn)
        if err == nil {
            _, chainkey , err := ResumeRatchetFromString(string(b))
            if err != nil { return hasupdatedsomething, fmt.Errorf("%s : %w", fn, err) }
            _ , _ , ratchetkey := Ratchet(docbytes, chainkey[:])
            err = ioutil.WriteFile(fn, []byte(ratchetkey.ToString()), 0644)
            if err != nil { return hasupdatedsomething, fmt.Errorf("%s : %w", fn, err) }
        }

        // update local .ikchain

        if len(nextbytes) != 0 {
            fn := filepath.Join(chaindir, fmt.Sprintf("%x.next", parenthash))
            err = ioutil.WriteFile(fn, nextbytes, 0644)
            if err != nil { return hasupdatedsomething, (fmt.Errorf("%s : %v\n", fn, err)) }
        }

        if len(nexthash) != 0 {
            fn := filepath.Join(chaindir, fmt.Sprintf("%x.next", parenthash))
            err = ioutil.WriteFile(fn, nexthash, 0644)
            if err != nil { return hasupdatedsomething, (fmt.Errorf("%s : %v\n", fn, err)) }
        }

        // finally update the document

        err = ioutil.WriteFile(document, nextbytes, 0644);
        if err != nil { return hasupdatedsomething, (fmt.Errorf("%s : %w", document, err))}

        hasupdatedsomething = true

        log.Printf("[ikdoc] %s %s\n", color.GreenString("✔ update"), nexthash)
    }
}

func httpdownload(
        ctx context.Context,
        vault identity.VaultI,
        urls []string,
        path string,
        expectedhash []byte,
        watch bool,
    ) ([]byte, error) {


    var err error
    var b   []byte
    var anyworked = false

    for _, url := range urls {


        if !strings.HasSuffix(url, "/") {
            url += "/"
        }
        nurl := url + path
        log.Println("[ikdoc] ☎ remote", nurl)

        b , err = httpdownload2(ctx, vault, nurl, watch)

        if err == nil {
            if b != nil {
                if expectedhash != nil {
                    h := sha256.New()
                    h.Write(b)
                    if subtle.ConstantTimeCompare(expectedhash[:], h.Sum(nil)) != 1 {
                        err = fmt.Errorf("%s : hash verification failed: %x", nurl, expectedhash[:])
                        log.Error(fmt.Errorf("[ikdoc] remote %w", err))
                        b = nil
                        continue
                    }
                }

                anyworked = true
                break
            } else {
                anyworked = true
            }
        } else {
            err = fmt.Errorf("%s : %v", nurl , err)
        }
    }

    if !anyworked && err != nil { return nil, err }
    return b, nil
}


func httpdownload2(
        ctx context.Context,
        vault identity.VaultI,
        url string,
        watch bool,
    ) ([]byte, error) {

    tls, err := iktls.NewTlsClient(vault)
    if err != nil { return nil, err }

    // this is fine, we don't actually care about TLS for anything but passing firewalls
    // the document we want is signed
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
