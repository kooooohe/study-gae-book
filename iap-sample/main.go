package main

import (
	"fmt"
	"net/http"
	"os"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// JWT
		jwtHeaderName := "x-goog-iap-jwt-assertion"

		tokenString := r.Header.Get(jwtHeaderName)
		w.WriteHeader(200)
		fmt.Fprintf(w, tokenString)
	})

	port := os.Getenv("PORT")

	if port == "" {
		port = "8080"
	}

	http.ListenAndServe(fmt.Sprintf(":%s", port), nil)
}
