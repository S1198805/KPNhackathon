package main

import (
    "fmt"
    "log"
    "net/http"
    "time"
)

func main() {
    mux := http.NewServeMux()

    mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "text/plain; charset=utf-8")
        fmt.Fprintln(w, "ok")
    })

    mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
        fmt.Fprintln(w, "# HELP upgrade_readiness_checker_info Information about the checker, not cluster readiness.")
        fmt.Fprintln(w, "# TYPE upgrade_readiness_checker_info gauge")
        fmt.Fprintln(w, `upgrade_readiness_checker_info{version="0.1.0"} 1`)
    })

    server := &http.Server{
        Addr:              ":8080",
        Handler:           mux,
        ReadHeaderTimeout: 5 * time.Second,
    }

    log.Println("Readiness checker listening on port 8080")
    log.Fatal(server.ListenAndServe())
}