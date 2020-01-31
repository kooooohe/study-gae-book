package main

import (
	"encoding/json"
	"fmt"
	jwt "gopkg.in/dgrijalva/jwt-go.v3"
	jose "gopkg.in/square/go-jose.v2"
	"io/ioutil"
	"net/http"
	"os"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		jwtHeaderName := "x-goog-iap-jwt-assertion"

		// JWURL of public key formated jwk
		jwtUrl := "https://www.gstatic.com/iap/verify/public_key-jwk"
		issuerUrl := "https://cloud.google.com/iap"
		audience := "/projects/326635093882/apps/my-project-83434-2"

		tokenString := r.Header.Get(jwtHeaderName)

		// get public key
		resp, err := http.Get(jwtUrl)
		defer resp.Body.Close()
		if err != nil {
			w.WriteHeader(500)
			fmt.Fprintln(w, err)
			return
		}

		//read public key
		keyBody, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			w.WriteHeader(500)
			fmt.Fprintln(w, err)
			return
		}

		//decode jwt
		token, err := jwt.Parse(tokenString,
			func(token *jwt.Token) (interface{}, error) {
				// check algorithm of sigunatur
				if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
					return nil,
						fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
				}

				// get jwt info
				claims := token.Claims.(jwt.MapClaims)
				// check audience, issuer
				if claims["iss"] != issuerUrl {
					return nil, fmt.Errorf("Invalid issuer: %v", claims["iss"])
				}

				if claims["aud"] != audience {
					return nil, fmt.Errorf("Invalid audience: %v", claims["aud"])
				}

				// parse public key
				var keySet jose.JSONWebKeySet
				err := json.Unmarshal(keyBody, &keySet)

				// get publikey matching kid of token
				kid := token.Header["kid"].(string)
				return keySet.Key(kid)[0].Key, err
			})

		if err != nil {
			w.WriteHeader(500)
			fmt.Fprintln(w, err)
			return
		}

		claims := token.Claims.(jwt.MapClaims)
		email := claims["email"]
		subject := claims["sub"]

		w.WriteHeader(200)
		fmt.Fprintln(w, email)
		fmt.Fprintln(w, subject)
	})

	port := os.Getenv("PORT")

	if port == "" {
		port = "8080"
	}

	http.ListenAndServe(fmt.Sprintf(":%s", port), nil)
}
