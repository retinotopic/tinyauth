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
	"github.com/retinotopic/tinyauth/provider"
	"golang.org/x/oauth2/google"
)

/*
Refresh renews the id token using the refresh token for Google OAuth2.
It sends a request to the Google token endpoint and updates the id token cookie.
*/
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

/*
RevokeRefresh sends a request to the Google revoke endpoint to invalidate the refresh token.
*/
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

/*
FetchUser verifies the ID token and extracts the user ID (subject) from the claims.
*/
func (p Provider) FetchUser(w http.ResponseWriter, r *http.Request) (string, error) {
	token, err := r.Cookie("token")
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return "", err
	}
	claims, err := p.VerifyToken([]byte(token.Value))

	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return "", err
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

/*
VerifyToken verifies the JWT token using the Google public key.
It attempts to verify the token with the current public key locally and, if unsuccessful, tries to fetch and use new public keys.
*/
func (p Provider) VerifyToken(tokenValue []byte) (*jwt.Claims, error) {
	if claims, err := jwt.RSACheck(tokenValue, p.PublicKey); err == nil {
		return claims, nil
	}

	for i := 0; i < 2; i++ {
		newKey, err := GetPublicKey(i)
		if err != nil {
			continue
		}

		if claims, err := jwt.RSACheck(tokenValue, newKey); err == nil {
			*p.PublicKey = *newKey
			return claims, nil
		}
	}

	return nil, errors.New("failed to verify token with all available keys")
}
