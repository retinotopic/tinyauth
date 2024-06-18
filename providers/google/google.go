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
	OauthStateString string
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
		OauthStateString: randfuncs.RandomString(20, randfuncs.NewSource()),
		PublicKey:        key,
		name:             "google",
	}, nil
}

func (p Provider) BeginAuthFlow(w http.ResponseWriter, r *http.Request) error {
	url := p.Config.AuthCodeURL(p.OauthStateString, oauth2.AccessTypeOffline)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect) // composing our auth request url
	return nil
}

func (p Provider) CompleteAuthFlow(w http.ResponseWriter, r *http.Request) (provider.Tokens, error) {
	tokens := provider.Tokens{}
	if r.FormValue("state") != p.OauthStateString {
		http.Error(w, "The oauth state was missing or invalid", http.StatusBadRequest)
		return tokens, errors.New("invalid oauth state")
	}
	code := r.FormValue("code")
	token, err := p.Config.Exchange(context.Background(), code)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return tokens, err
	}
	tokens.Token = token.Extra("Token").(string)
	tokens.RefreshToken = token.RefreshToken
	if len(tokens.Token) == 0 || len(tokens.RefreshToken) == 0 {
		http.Error(w, "tokens are empty", http.StatusBadRequest)
		return tokens, fmt.Errorf("tokens is empty")
	}
	Token := http.Cookie{Name: "token", Value: tokens.Token, MaxAge: 3600, HttpOnly: true, Secure: true}
	RefreshToken := http.Cookie{Name: "refresh_token", Value: tokens.RefreshToken, HttpOnly: true, Secure: true}
	http.SetCookie(w, &Token)
	http.SetCookie(w, &RefreshToken)
	w.WriteHeader(http.StatusOK)
	return tokens, err
}
