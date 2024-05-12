package gfirebase

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/retinotopic/TinyAuth/provider"
)

func (p Provider) Refresh(w http.ResponseWriter, r *http.Request) error {
	tokens := &provider.Tokens{}
	form := url.Values{}
	token, err := r.Cookie("RefreshToken")
	if err != nil {
		log.Println(err, "revoke cookie retrieve err")
	}
	form.Add("refresh_token", token.Value)
	form.Add("grant_type", "refresh_token")
	req, err := http.NewRequest("POST", p.RefreshTokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	err = json.NewDecoder(resp.Body).Decode(&tokens)
	if err != nil {
		return err
	}

	Token := http.Cookie{Name: "Token", Value: tokens.Token, MaxAge: 3600, Path: "/", HttpOnly: true, Secure: true}
	http.SetCookie(w, &Token)
	return nil
}
func (p Provider) RevokeRefresh(w http.ResponseWriter, r *http.Request) error {
	c, err := r.Cookie("Token")
	if err != nil {
		return err
	}
	token, err := p.Client.VerifyIDToken(context.Background(), c.Value)
	if err != nil {
		return err
	}
	err = p.Client.RevokeRefreshTokens(context.Background(), token.UID)
	if err != nil {
		return err
	}
	return nil
}
func (p Provider) FetchUser(w http.ResponseWriter, r *http.Request) (string, error) {
	c, err := r.Cookie("Token")
	if err != nil {
		return "", err
	}
	token, err := p.Client.VerifyIDToken(context.Background(), c.Value)
	if err != nil {
		return "", err
	}
	return token.UID, nil
}
