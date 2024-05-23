package google

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pascaldekloe/jwt"
	"github.com/retinotopic/TinyAuth/provider"
	"golang.org/x/oauth2/google"
)

func (p Provider) Refresh(w http.ResponseWriter, r *http.Request) error {
	tokens := &provider.Tokens{}
	form := url.Values{}
	token, err := r.Cookie("RefreshToken")
	if err != nil {
		return err
	}
	form.Add("refresh_token", token.Value)
	form.Add("grant_type", "refresh_token")
	form.Add("client_id", p.Config.ClientID)
	form.Add("client_secret", p.Config.ClientSecret)
	req, err := http.NewRequest("POST", google.Endpoint.TokenURL, strings.NewReader(form.Encode()))
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

	Token := http.Cookie{Name: "Token", Value: tokens.Token, MaxAge: 3600, HttpOnly: true, Secure: true}
	http.SetCookie(w, &Token)
	return nil

}
func (p Provider) RevokeRefresh(w http.ResponseWriter, r *http.Request) error {
	form := url.Values{}
	token, err := r.Cookie("RefreshToken")
	if err != nil {
		return err
	}
	form.Add("token", token.Value)
	req, err := http.NewRequest("POST", p.RevokeURL, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	w.WriteHeader(resp.StatusCode)
	return nil
}
func (p Provider) FetchUser(w http.ResponseWriter, r *http.Request) (string, error) {
	token, err := r.Cookie("token")
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return "", err
	}
	claims, err := jwt.RSACheck([]byte(token.Value), p.PublicKey)
	if err != nil {
		key, err := GetPublicKey()
		if err != nil {
			return "", err
		}
		claims, err = jwt.RSACheck([]byte(token.Value), key)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return "", err
		}
		*p.PublicKey = *key

	}
	if !claims.Valid(time.Now()) {
		w.WriteHeader(http.StatusBadRequest)
		return "", errors.New("invalid claims")
	}

	if claims.Issuer != "https://accounts.google.com" && claims.Issuer != "accounts.google.com" {
		w.WriteHeader(http.StatusBadRequest)
		return "", errors.New("invalid issuer")
	}

	if !claims.AcceptAudience(p.Config.ClientID) {
		w.WriteHeader(http.StatusBadRequest)
		return "", errors.New("invalid audience")
	}

	return claims.Subject, nil
}
