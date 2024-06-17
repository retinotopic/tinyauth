package google

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pascaldekloe/jwt"
	"github.com/retinotopic/TinyAuth/provider"
	"golang.org/x/oauth2/google"
)

func (p Provider) Refresh(w http.ResponseWriter, r *http.Request) (provider.Tokens, error) {
	tokens := provider.Tokens{}
	form := url.Values{}
	token, err := r.Cookie("refresh_token")
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return tokens, err
	}
	form.Add("refresh_token", token.Value)
	form.Add("grant_type", "refresh_token")
	form.Add("client_id", p.Config.ClientID)
	form.Add("client_secret", p.Config.ClientSecret)
	req, err := http.NewRequest("POST", google.Endpoint.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return tokens, err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return tokens, err
	}
	m := make(map[string]interface{})
	err = json.NewDecoder(resp.Body).Decode(&m)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return tokens, err
	}
	fmt.Println(m)
	val, ok := m["id_token"]
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		return tokens, fmt.Errorf("tokens is empty")
	}
	tokens.Token = val.(string)
	Token := http.Cookie{Name: "token", Value: tokens.Token, MaxAge: 3600, HttpOnly: true, Secure: true}
	http.SetCookie(w, &Token)
	w.WriteHeader(http.StatusOK)
	return tokens, err

}
func (p Provider) RevokeRefresh(w http.ResponseWriter, r *http.Request) error {
	form := url.Values{}
	token, err := r.Cookie("refresh_token")
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return err
	}
	form.Add("token", token.Value)
	req, err := http.NewRequest("POST", p.RevokeURL, strings.NewReader(form.Encode()))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
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
	fmt.Println(token.Value, "this")
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
