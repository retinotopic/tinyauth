package google

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"net/http"

	"github.com/retinotopic/pokerGO/pkg/randfuncs"
	"github.com/retinotopic/tinyauth/provider"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// Private t for easy parsing
type tokens struct {
	Token        string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
}

type Provider struct {
	Config           oauth2.Config
	RevokeURL        string
	OauthStateString string
	PublicKey        *rsa.PublicKey
	RefreshPath      string
}

/*
Creates Google OAuth2 OIDC provider (SSO).
*/
func New(ctx context.Context, clientid string, clientsecret, redirect string, refreshPath string) (Provider, error) {
	key, err := GetPublicKey(ctx, 1)
	if err != nil {
		return Provider{}, err
	}
	return Provider{
		Config: oauth2.Config{
			ClientID:     clientid,
			ClientSecret: clientsecret,
			RedirectURL:  redirect,
			Scopes:       []string{"openid"},
			Endpoint:     google.Endpoint,
		},
		RevokeURL:        "https://accounts.google.com/o/oauth2/revoke",
		OauthStateString: randfuncs.RandomString(20, randfuncs.NewSource()),
		PublicKey:        key,
		RefreshPath:      refreshPath,
	}, nil
}

/*
BeginAuth starts the Google OAuth2 authorization process.
It redirects the user to the Google authorization page.
*/
func (p Provider) BeginAuth(w http.ResponseWriter, r *http.Request) error {
	url := p.Config.AuthCodeURL(p.OauthStateString, oauth2.AccessTypeOffline)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect) // composing our auth request url
	return nil
}

/*
CompleteAuth finishes the Google OAuth2 authorization process.
It exchanges the authorization code for refresh token and id token.
*/
func (p Provider) CompleteAuth(w http.ResponseWriter, r *http.Request) (provider.Tokens, error) {
	t := provider.Tokens{}
	if r.FormValue("state") != p.OauthStateString {
		http.Error(w, "The oauth state was missing or invalid", http.StatusBadRequest)
		return t, errors.New("invalid oauth state")
	}
	code := r.FormValue("code")
	fmt.Println(code)
	token, err := p.Config.Exchange(r.Context(), code)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return t, err
	}
	t.Token = token.Extra("id_token").(string)
	t.RefreshToken = token.RefreshToken
	if len(t.Token) == 0 || len(t.RefreshToken) == 0 {
		http.Error(w, "t are empty", http.StatusBadRequest)
		return t, fmt.Errorf("t is empty")
	}
	fmt.Println(t)
	Token := http.Cookie{Name: "token", Value: t.Token, MaxAge: 3600, HttpOnly: true, Secure: true}
	RefreshToken := http.Cookie{Name: "refresh_token", Value: t.RefreshToken, HttpOnly: true, Secure: true, Path: p.RefreshPath}
	http.SetCookie(w, &Token)
	http.SetCookie(w, &RefreshToken)
	w.WriteHeader(http.StatusOK)
	return t, err
}
