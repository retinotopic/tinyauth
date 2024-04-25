package gfirebase

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"strings"
)

func (p Provider) Refresh(w http.ResponseWriter, r *http.Request) {
	tokens := make(map[string]string)
	form := url.Values{}
	token, err := r.Cookie("refreshToken")
	if err != nil {
		log.Println(err, "revoke cookie retrieve err")
	}
	form.Add("refresh_token", token.Value)
	form.Add("grant_type", "refresh_token")
	req, err := http.NewRequest("POST", p.RefreshTokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		log.Println(err, "error creating request error")
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Println(err, "error request error")
	}
	err = json.NewDecoder(resp.Body).Decode(&tokens)
	if err != nil {
		log.Println(err, "json decode error")
	}

	idToken := http.Cookie{Name: "idToken", Value: tokens["IdToken"], MaxAge: 3600, Path: "/", HttpOnly: true, Secure: true}
	refreshToken := http.Cookie{Name: "refreshToken", Value: tokens["RefreshToken"], Path: "/refresh", HttpOnly: true, Secure: true}
	http.SetCookie(w, &idToken)
	http.SetCookie(w, &refreshToken)
	////
	log.Println(resp.StatusCode)
}
func (p Provider) RevokeRefresh(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("idToken")
	if err != nil {
		log.Println(err, "revoke cookie retrieve err")
	}
	token, err := p.Client.VerifyIDToken(context.Background(), c.Value)
	if err != nil {
		log.Println(err, "verify id token err")
	}
	err = p.Client.RevokeRefreshTokens(context.Background(), token.UID)
	if err != nil {
		log.Println(err, "revoke refresh token err")
	}
}
func (p Provider) FetchUser(w http.ResponseWriter, r *http.Request) string {
	c, err := r.Cookie("idToken")
	if err != nil {
		log.Println(err, "revoke cookie retrieve err")
	}
	token, err := p.Client.VerifyIDToken(context.Background(), c.Value)
	if err != nil {
		log.Println(err, "verify id token err")
	}
	return token.UID
}
