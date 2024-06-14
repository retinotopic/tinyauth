package google

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"net/http"

	"github.com/retinotopic/TinyAuth/provider"
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
	key, err := GetPublicKey()
	if err != nil {
		return Provider{}, err
	}
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
		PublicKey:        key,
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
	tokens := provider.Tokens{}
	tokens.Token = token.Extra("Token").(string)
	tokens.RefreshToken = token.RefreshToken
	if len(tokens.Token) == 0 || len(tokens.RefreshToken) == 0 {
		return fmt.Errorf("tokens is empty")
	}
	Token := http.Cookie{Name: "Token", Value: tokens.Token, MaxAge: 3600, HttpOnly: true, Secure: true}
	RefreshToken := http.Cookie{Name: "RefreshToken", Value: tokens.RefreshToken, HttpOnly: true, Secure: true}
	http.SetCookie(w, &Token)
	http.SetCookie(w, &RefreshToken)
	w.WriteHeader(http.StatusOK)
	return nil
}
