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
		http.Error(w, err.Error(), http.StatusBadRequest)
		return tokens, err
	}
	form.Add("refresh_token", token.Value)
	form.Add("grant_type", "refresh_token")
	form.Add("client_id", p.Config.ClientID)
	form.Add("client_secret", p.Config.ClientSecret)
	req, err := http.NewRequest("POST", google.Endpoint.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return tokens, err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return tokens, err
	}
	m := make(map[string]interface{})
	err = json.NewDecoder(resp.Body).Decode(&m)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return tokens, err
	}
	tokens.Token, _ = m["id_token"].(string)
	if len(tokens.Token) == 0 {
		errstr, err := json.Marshal(m["error"])
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return tokens, err
		}
		http.Error(w, string(errstr), http.StatusBadRequest)
		return tokens, fmt.Errorf("%v", string(errstr))
	}
	Token := http.Cookie{Name: "token", Value: tokens.Token, MaxAge: 3600, HttpOnly: true, Secure: true}
	http.SetCookie(w, &Token)
	w.WriteHeader(http.StatusOK)
	return tokens, err

}
func (p Provider) RevokeRefresh(w http.ResponseWriter, r *http.Request) error {
	form := url.Values{}
	token, err := r.Cookie("refresh_token")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return err
	}
	form.Add("token", token.Value)
	req, err := http.NewRequest("POST", p.RevokeURL, strings.NewReader(form.Encode()))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return err
	}

	m := make(map[string]interface{})
	err = json.NewDecoder(resp.Body).Decode(&m)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return err
	}
	_, ok := m["error"]
	if ok {
		errstr, err := json.Marshal(m["error"])
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return err
		}
		http.Error(w, string(errstr), http.StatusBadRequest)
		return fmt.Errorf("%v", string(errstr))
	}

	w.WriteHeader(http.StatusOK)
	return nil
}
func (p Provider) FetchUser(w http.ResponseWriter, r *http.Request) (string, error) {
	token, err := r.Cookie("token")
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
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
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return "", err
		}
		*p.PublicKey = *key

	}
	if !claims.Valid(time.Now()) {
		http.Error(w, "invalid jwt claims", http.StatusUnauthorized)
		return "", errors.New("invalid jwt claims")
	}

	if claims.Issuer != "https://accounts.google.com" && claims.Issuer != "accounts.google.com" {
		http.Error(w, "invalid jwt claims", http.StatusUnauthorized)
		return "", errors.New("invalid jwt claims")
	}

	if !claims.AcceptAudience(p.Config.ClientID) {
		http.Error(w, "invalid jwt claims", http.StatusUnauthorized)
		return "", errors.New("invalid jwt claims")
	}

	return claims.Subject, nil
}
