package main




import (
	"log"
	"net/http"
    "github.com/devguardio/ikdoc"
    "path"
    "github.com/go-chi/chi/v5/middleware"

)

func cleanPath(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        r.URL.Path      = path.Clean(r.URL.Path)
        r.URL.RawPath   = path.Clean(r.URL.RawPath)
		next.ServeHTTP(w, r)
	})
}

func Serve(ikchaindir string) {
	log.Println("Listening on ::5280")
	err := http.ListenAndServe(":5280",
        cleanPath(
        middleware.Logger(
        ikdoc.Server(ikchaindir),
        )))
	if err != nil {
		log.Fatal(err)
	}
}
