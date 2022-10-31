package controller

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
)

var jwtKey = []byte("my_secret_key")

var users = map[string]string{
	"user1": "password1",
	"user2": "password2",
}

// to read username and password from the request
type Credentials struct {
	Password string `json:"password"`
	UserName string `json:"username"`
}

// encoded to a jwt
// jwt.standardclaims as an embedded , provide expiry
type Claims struct {
	UserName string `json:"username"`
	jwt.StandardClaims
}

func SignIn(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("-----1----")
	var creds Credentials
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		log.Fatal(err)
		return
	}

	// get the expected password from our in memory map
	expectedPassword, ok := users[creds.UserName]

	if !ok || expectedPassword != creds.Password {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	fmt.Printf("-----2----")


	// declare espiration time of the token
	// we kept it as 5 minutes

	expirationTime := time.Now().Add(5 * time.Minute)

	//	create jwt claims, which includes username, expiry time
	fmt.Printf("----3----")

	Claims := &Claims{
		UserName: creds.UserName,
		StandardClaims: jwt.StandardClaims{
			// IN jwt expiry time is expressed in unix milliseconds
			ExpiresAt: expirationTime.Unix(),
		},
	}

	fmt.Printf("----3.1----")


	// declare token with alg used for signing and the claims

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, Claims)

	// create jwt string
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		// log.Fatal(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	fmt.Printf("-----4----")

	// setup client cookie for token

	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Value:   tokenString,
		Expires: expirationTime,
	})
	fmt.Printf("-----5----")

}

func Welcome(w http.ResponseWriter, r *http.Request) {
	// obtain session tokenfrom cookies
	c, err := r.Cookie("token")

	if err != nil {
		if err == http.ErrNoCookie {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// get jwt string from cookie
	tknString := c.Value

	// initialize new claims
	Claims := &Claims{}

	// parse jwt str and store it to claims
	tkn, err := jwt.ParseWithClaims(tknString, Claims, func(t *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if !tkn.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// return welcome message to user , along with username given in the token

	w.Write([]byte(fmt.Sprintf("welcome %s", Claims.UserName)))
}

func Refresh(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("token")
	if err != nil {
		if err == http.ErrNoCookie {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	tknString := c.Value

	Claims := &Claims{}

	tkn, err := jwt.ParseWithClaims(tknString, Claims, func(t *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if !tkn.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if time.Unix(Claims.ExpiresAt, 0).Sub(time.Now()) > 30*time.Second {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	expirationTime := time.Now().Add(5 * time.Minute)
	Claims.ExpiresAt = expirationTime.Unix()
	token := jwt.NewWithClaims(jwt.SigningMethodES256, Claims)

	tkstr, err := token.SignedString(jwtKey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Value:   tkstr,
		Expires: expirationTime,
	})

}
