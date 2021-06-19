package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/context"
	"github.com/gorilla/mux"
)

// Run ./genSecret.sh to create private key
var (
	SECRET_FILE = "secret.pem"
	KEY         string
)

func init() {
	KEY = initSecretKey()

}

func initSecretKey() string {
	file, err := os.Open(SECRET_FILE)
	if err != nil {
		panic(err)
	}

	content, _ := io.ReadAll(file)

	secret := strings.TrimSpace(string(content))
	secret = strings.TrimPrefix(string(secret), "-----BEGIN RSA PRIVATE KEY-----")
	secret = strings.TrimSuffix(string(secret), "-----END RSA PRIVATE KEY-----")

	return secret
}

func verifyToken(tokenString string) (string, error) {
	// Verify
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(KEY), nil
	})

	if err != nil {

		if ve, ok := err.(*jwt.ValidationError); ok {
			if ve.Errors&(jwt.ValidationErrorExpired|jwt.ValidationErrorNotValidYet) != 0 {

				return "", errors.New("token expired")
			}
		}

		return "", errors.New("invalid token")

	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		userid := claims["aud"]
		if v, ok := userid.(string); ok {
			log.Println("Token is valid.")
			return v, nil
		}

	}

	return "", errors.New("Unknown error")

}

func genToken(secret string) (string, error) {
	// A JWT Token comprises of:
	// Header (signing method, algorithm etc)
	// .
	// Payload (claims)
	// .
	// Sign
	// HMACSHA256(
	// 	base64UrlEncode(header) + "." +
	// 	base64UrlEncode(payload),
	// 	secret)

	mySigningKey := []byte(secret)
	expiryDate := time.Now().Add(time.Hour * 24 * 7).Unix()

	// Create the Claims
	claims := &jwt.StandardClaims{
		Audience:  "123",
		ExpiresAt: expiryDate,
		Issuer:    "test",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	ss, err := token.SignedString(mySigningKey)
	if err != nil {
		panic(err)
	}

	return ss, nil
}

func ProductHandler(w http.ResponseWriter, r *http.Request) {
	// get user id
	userid := context.Get(r, "userid")

	w.Header().Add("Content-Type", "text/html")
	bodyHTML := fmt.Sprintf("<h1>Hello, %s</h1>", userid)
	w.Write([]byte(bodyHTML))
}

var GateKeeperMux = mux.MiddlewareFunc(func(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// Reject anything other than Bearer
		mechanism := strings.Split(r.Header.Get("Authorization"), " ") // []string{"Bearer", "TOKEN_STRING"}
		if len(mechanism) > 1 && mechanism[0] == "Bearer" {
			if token := mechanism[1]; token != "" {

				// validate token
				userid, err := verifyToken(token)
				if err != nil {

					if err.Error() == "token expired" {
						http.Error(w, err.Error(), http.StatusUnauthorized)
						return
					} else {
						http.Error(w, "Invalid Token", http.StatusUnauthorized)

						return
					}

				}
				// set context
				context.Set(r, "userid", userid)
				h.ServeHTTP(w, r)
				return

			}

		}

		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("401 - Status Unauthorized"))

	})
})

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	// Simulate login = true
	w.Header().Set("Content-Type", "text/html")

	JWTtoken, _ := genToken(KEY)

	cookie1 := http.Cookie{
		Name:     "userToken",
		Value:    JWTtoken,
		HttpOnly: true, // true = accessible only via HTTP

	}

	http.SetCookie(w, &cookie1)

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Token created!"))

}

func main() {

	router := mux.NewRouter()

	protectedRoute := router.NewRoute().Subrouter()
	protectedRoute.
		// PathPrefix("/api/v1/").
		Path("/products").
		Methods("GET").
		HandlerFunc(ProductHandler)

	// Implement middleware
	protectedRoute.Use(GateKeeperMux)

	router.HandleFunc("/login", LoginHandler)

	log.Fatal(http.ListenAndServe(":8080", router))
}
