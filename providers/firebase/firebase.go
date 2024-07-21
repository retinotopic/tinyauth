package firebase

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/goccy/go-json"

	firebase "firebase.google.com/go/v4"
	"firebase.google.com/go/v4/auth"
	"github.com/retinotopic/tinyauth/provider"
	"google.golang.org/api/option"
)

type Provider struct {
	Client             *auth.Client
	WebApiKey          string
	RedirectURL        string
	SendOobCodeURL     string
	SignInWithEmailURL string
	RefreshTokenURL    string
	RefreshPath        string
}

/*
Creates firebase OIDC provider (Sign In via Email link).
In the "credentials" parameter you need to specify the path to the json file with firebase credentials
*/
func New(webapikey string, credentials string, redirect string, refreshPath string) (Provider, error) {
	opt := option.WithCredentialsFile(credentials)

	app, err := firebase.NewApp(context.Background(), nil, opt)
	if err != nil {
		return Provider{}, nil
	}
	client, err := app.Auth(context.Background())
	if err != nil {
		return Provider{}, nil
	}
	return Provider{
		Client:             client,
		WebApiKey:          webapikey,
		RedirectURL:        redirect,
		SendOobCodeURL:     "https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key=",
		SignInWithEmailURL: "https://identitytoolkit.googleapis.com/v1/accounts:signInWithEmailLink?key=",
		RefreshTokenURL:    "https://securetoken.googleapis.com/v1/token?key=",
		RefreshPath:        refreshPath,
	}, nil
}

// Sends a "Magic link" to the Email entered in the form
func (p Provider) BeginAuth(w http.ResponseWriter, r *http.Request) error {
	form := url.Values{}
	form.Add("requestType", "EMAIL_SIGNIN")
	form.Add("email", r.FormValue("email"))
	form.Add("continueUrl", p.RedirectURL)
	req, err := http.NewRequest("POST", p.SendOobCodeURL+p.WebApiKey, strings.NewReader(form.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return err
	}
	m := make(map[string]interface{})
	err = json.NewDecoder(resp.Body).Decode(&m)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return err
	}
	_, ok := m["email"]
	if !ok {
		errstr, err := json.Marshal(m["error"])
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return err
		}
		http.Error(w, string(errstr), http.StatusBadRequest)
		return fmt.Errorf("%v", string(errstr))
	}

	c := &http.Cookie{
		Name:     "email",
		Value:    r.FormValue("email"),
		Path:     "/",
		HttpOnly: true,
	}
	w.WriteHeader(http.StatusOK)
	http.SetCookie(w, c)

	return nil
}

/*
CompleteAuth finishes the sign in process after the user clicks the email link.
It verifies the OOB code and retrieves tokens.
*/
func (p Provider) CompleteAuth(w http.ResponseWriter, r *http.Request) (provider.Tokens, error) {
	tokens := provider.Tokens{}
	c, err := r.Cookie("email")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return tokens, err
	}
	oobCode := r.URL.Query().Get("oobCode")

	form := url.Values{}
	form.Add("oobCode", oobCode)
	form.Add("email", c.Value)
	req, err := http.NewRequest("POST", p.SignInWithEmailURL+p.WebApiKey, strings.NewReader(form.Encode()))
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
		http.Error(w, err.Error(), http.StatusBadRequest)
		return tokens, err
	}
	tokens.Token = m["idToken"].(string)
	tokens.RefreshToken = m["refreshToken"].((string))
	if len(tokens.RefreshToken) == 0 || len(tokens.Token) == 0 {
		errstr, err := json.Marshal(m["error"])
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return tokens, err
		}
		http.Error(w, string(errstr), http.StatusBadRequest)
		return tokens, fmt.Errorf("%v", string(errstr))
	}
	Token := http.Cookie{Name: "token", Value: tokens.Token, MaxAge: 3600, HttpOnly: true, Secure: true}
	RefreshToken := http.Cookie{Name: "refresh_token", Value: tokens.RefreshToken, HttpOnly: true, Secure: true, Path: p.RefreshPath}
	http.SetCookie(w, &Token)
	http.SetCookie(w, &RefreshToken)
	c = &http.Cookie{
		Name:     "email",
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
	}
	http.SetCookie(w, c)
	w.WriteHeader(http.StatusOK)

	return tokens, err
}
