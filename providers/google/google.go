package google

import (
	"context"
	"crypto/rsa"
	"fmt"
	"log"
	"math/big"
	"net/http"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/retinotopic/pokerGO/pkg/randfuncs"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type Provider struct {
	Name             string
	Config           oauth2.Config
	RevokeURL        string
	oauthStateString string
	PublicKey        *rsa.PublicKey
}

func New(clientid string, clientsecret, redirect string) Provider {
	req, err := http.NewRequest("GET", "https://www.googleapis.com/oauth2/v2/certs", nil)
	if err != nil {
		log.Println(err, "error creating request error")
	}
	resp, err := http.DefaultClient.Do(req)

	if err != nil {
		log.Println(err, "request error")
	}
	set, err := jwk.ParseReader(resp.Body)
	if err != nil {
		log.Println(err, "jwk parse error")
	}
	key, ok1 := set.Get(0)
	n, ok2 := key.Get("n")
	e, ok3 := key.Get("e")
	if !ok1 || !ok2 || !ok3 {
		log.Println("jwk parse error")
	}
	bn := new(big.Int)
	BN := bn.SetBytes(n.([]byte))
	return Provider{
		Config: oauth2.Config{
			ClientID:     clientid,
			ClientSecret: clientsecret,
			RedirectURL:  redirect,
			Scopes:       []string{"email openid"},
			Endpoint:     google.Endpoint,
		},
		RevokeURL:        "https://accounts.google.com/o/oauth2/revoke",
		oauthStateString: randfuncs.RandomString(20, randfuncs.NewSource()),
		PublicKey:        &rsa.PublicKey{N: BN, E: e.(int)},
	}
}

func (p Provider) BeginLoginCreate(w http.ResponseWriter, r *http.Request) {
	url := p.Config.AuthCodeURL(p.oauthStateString, oauth2.AccessTypeOffline)
	fmt.Println(url)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect) // composing our auth request url
}

func (p Provider) CompleteLoginCreate(w http.ResponseWriter, r *http.Request) {
	if r.FormValue("state") != p.oauthStateString {
		fmt.Println("invalid oauth state")
	}
	code := r.FormValue("code")
	token, err := p.Config.Exchange(context.Background(), code)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	idToken := http.Cookie{Name: "idToken", Value: token.Extra("id_token").(string), MaxAge: 3600, Path: "/", HttpOnly: true, Secure: true}
	refreshToken := http.Cookie{Name: "refreshToken", Value: token.RefreshToken, Path: "/refresh", HttpOnly: true, Secure: true}
	providerC := http.Cookie{Name: "provider", Value: "gfirebase", Path: "/", HttpOnly: true, Secure: true}
	http.SetCookie(w, &idToken)
	http.SetCookie(w, &refreshToken)
	http.SetCookie(w, &providerC)

	//////////////
	fmt.Println(token.Expiry)
	fmt.Println(token.Extra("id_token"), "extra")
	w.WriteHeader(http.StatusOK)
}
