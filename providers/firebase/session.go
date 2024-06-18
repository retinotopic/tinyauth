package firebase

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/retinotopic/TinyAuth/provider"
)

func (p Provider) Refresh(w http.ResponseWriter, r *http.Request) (provider.Tokens, error) {
	tokens := provider.Tokens{}
	form := url.Values{}
	token, err := r.Cookie("refresh_token")
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
	}
	form.Add("refresh_token", token.Value)
	form.Add("grant_type", "refresh_token")
	req, err := http.NewRequest("POST", p.RefreshTokenURL+p.WebApiKey, strings.NewReader(form.Encode()))
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
	tokens.Token, _ = m["idToken"].(string)
	if len(tokens.Token) == 0 {
		errstr, err := json.Marshal(m["error"])
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return tokens, err
		}
		http.Error(w, string(errstr), http.StatusBadRequest)
		return tokens, fmt.Errorf("%v", string(errstr))
	}
	Token := http.Cookie{Name: "token", Value: tokens.Token, MaxAge: 3600, Path: "/", HttpOnly: true, Secure: true}
	http.SetCookie(w, &Token)
	w.WriteHeader(http.StatusOK)
	return tokens, err
}
func (p Provider) RevokeRefresh(w http.ResponseWriter, r *http.Request) error {
	c, err := r.Cookie("refresh_token")
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return err
	}
	token, err := p.Client.VerifyIDToken(context.Background(), c.Value)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return err
	}
	err = p.Client.RevokeRefreshTokens(context.Background(), token.UID)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return err
	}
	w.WriteHeader(http.StatusOK)
	return nil
}
func (p Provider) FetchUser(w http.ResponseWriter, r *http.Request) (string, error) {
	c, err := r.Cookie("token")
	if err != nil {
		return "", err
	}
	token, err := p.Client.VerifyIDToken(context.Background(), c.Value)
	if err != nil {
		return "", err
	}
	return token.UID, nil
}
