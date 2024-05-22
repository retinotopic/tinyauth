package google

import (
	"context"
	"crypto/rsa"
	"errors"
	"math/big"
	"net/http"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/retinotopic/pokerGO/pkg/randfuncs"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type Provider struct {
	name             string
	Config           oauth2.Config
	RevokeURL        string
	oauthStateString string
	PublicKey        *rsa.PublicKey
}

func New(clientid string, clientsecret, redirect string) (Provider, error) {
	req, err := http.NewRequest("GET", "https://www.googleapis.com/oauth2/v2/certs", nil)
	if err != nil {
		return Provider{}, err
	}
	resp, err := http.DefaultClient.Do(req)

	if err != nil {
		return Provider{}, err
	}
	set, err := jwk.ParseReader(resp.Body)
	if err != nil {
		return Provider{}, err
	}
	key, ok1 := set.Get(0)
	n, ok2 := key.Get("n")
	e, ok3 := key.Get("e")
	if !ok1 || !ok2 || !ok3 {
		return Provider{}, errors.New("jwk parse error")
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
		name:             "google",
	}, nil
}

func (p Provider) BeginAuthFlow(w http.ResponseWriter, r *http.Request) error {
	url := p.Config.AuthCodeURL(p.oauthStateString, oauth2.AccessTypeOffline)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect) // composing our auth request url
	return nil
}

func (p Provider) CompleteAuthFlow(w http.ResponseWriter, r *http.Request) error {
	if r.FormValue("state") != p.oauthStateString {
		return errors.New("invalid oauth state")
	}
	code := r.FormValue("code")
	token, err := p.Config.Exchange(context.Background(), code)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return err
	}
	Token := http.Cookie{Name: "Token", Value: token.Extra("Token").(string), MaxAge: 3600, HttpOnly: true, Secure: true}
	RefreshToken := http.Cookie{Name: "RefreshToken", Value: token.RefreshToken, HttpOnly: true, Secure: true}
	http.SetCookie(w, &Token)
	http.SetCookie(w, &RefreshToken)
	w.WriteHeader(http.StatusOK)
	return nil
}
