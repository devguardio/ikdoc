package ikdoc

import (
	"log"
	"net/http"
    "strings"
    "path/filepath"
    "path"
    "os"
    "fmt"
    "io"
    "github.com/fsnotify/fsnotify"
    "time"
    badrand "math/rand"
)

func servefile(f *os.File, w http.ResponseWriter, r *http.Request) {
    d, err := f.Stat()
    if err != nil {
        http.Error(w, "Not Found", http.StatusNotFound)
        return
    }

    w.Header().Set("Content-Length", fmt.Sprintf("%d", d.Size()))
    io.CopyN(w, f, d.Size())
}



func wait(ikchaindir string) {
    watcher, err := fsnotify.NewWatcher()
    if err != nil { panic(err) }
    defer watcher.Close()

    err = watcher.Add(ikchaindir)
    if err != nil { panic(err ) }

    select {
    case <- watcher.Events:
    case err, _ := <- watcher.Errors:
        log.Println(err)
    }
}

func Server(ikchaindir string) http.Handler {


    notify := make(chan struct{})
    go func() {
        for ;;{
            wait(ikchaindir)
            close(notify)
            notify = make(chan struct{})
        }
    }()


    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

        upath := path.Clean("/" + r.URL.Path)

        if strings.Contains(upath, "..") {
            http.Error(w, "Not Found", http.StatusNotFound)
            return
        }

        if strings.HasPrefix(upath, "/.ikchain/") {
            upath = r.URL.Path[len("/.ikchain/"):]
        }

        upath = filepath.Join(ikchaindir, filepath.FromSlash(upath))
        log.Println("request for", upath);



        f, err := os.Open(upath)
        if err == nil {
            defer f.Close()
            servefile(f, w, r)
            return
        }

        if r.Header.Get("Wait") != "" {

            dur, _  := time.ParseDuration(r.Header.Get("Wait"))
            if dur < time.Second {
                dur = time.Second
            }
            if dur > time.Minute {
                dur = time.Minute
            }

            select {
            case <- notify:
            case <- time.After(dur + time.Millisecond * time.Duration(badrand.Intn(100))):
            }

            f, err := os.Open(upath)
            if err == nil {
                defer f.Close()
                servefile(f, w, r)
                return
            }
        }

        http.Error(w, "Not Found", http.StatusNotFound)
        return

    })
}

