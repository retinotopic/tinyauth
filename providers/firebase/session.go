package firebase

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/retinotopic/tinyauth/provider"
)

/*
Refresh renews the ID tokens using the refresh token.
It sends a request to the Firebase refresh token endpoint.
*/
func (p Provider) Refresh(w http.ResponseWriter, r *http.Request) (provider.Tokens, error) {
	t := provider.Tokens{}
	tkns := tokens{}
	form := url.Values{}
	token, err := r.Cookie("refresh_token")
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
	}
	form.Add("refresh_token", token.Value)
	form.Add("grant_type", "refresh_token")
	req, err := http.NewRequest("POST", p.RefreshTokenURL+p.WebApiKey, strings.NewReader(form.Encode()))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return t, err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return t, err
	}
	if resp.StatusCode != 200 {
		http.Error(w, resp.Status, resp.StatusCode)
		return t, fmt.Errorf("%v", resp.Status)
	}
	err = json.NewDecoder(resp.Body).Decode(&tkns)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return t, err
	}
	t.Token = tkns.Token
	Token := http.Cookie{Name: "token", Value: t.Token, MaxAge: 3600, Path: "/", HttpOnly: true, Secure: true}
	http.SetCookie(w, &Token)
	w.WriteHeader(http.StatusOK)
	return t, err
}

/*
RevokeRefresh verifies the ID token and uses the Firebase Admin SDK to revoke the refresh tokens.
*/
func (p Provider) RevokeRefresh(w http.ResponseWriter, r *http.Request) error {
	c, err := r.Cookie("token")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return err
	}
	token, err := p.Client.VerifyIDToken(r.Context(), c.Value)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return err
	}
	err = p.Client.RevokeRefreshTokens(r.Context(), token.UID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return err
	}
	w.WriteHeader(http.StatusOK)
	return nil
}

/*
FetchUser verifies the ID token and extracts the user ID.
*/
func (p Provider) FetchUser(w http.ResponseWriter, r *http.Request) (string, error) {
	c, err := r.Cookie("token")
	if err != nil {
		return "", err
	}
	token, err := p.Client.VerifyIDToken(r.Context(), c.Value)
	if err != nil {
		tokens, err := p.Refresh(w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return "", err
		}
		token, err = p.Client.VerifyIDToken(r.Context(), tokens.Token)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return "", err
		}
	}
	return token.UID, nil
}
