package gfirebase

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	firebase "firebase.google.com/go/v4"
	"firebase.google.com/go/v4/auth"
	"github.com/retinotopic/TinyAuth/provider"
	"github.com/retinotopic/pokerGO/pkg/randfuncs"
	"google.golang.org/api/option"
)

type Provider struct {
	name               string
	Client             *auth.Client
	oauthStateString   string
	WebApiKey          string
	RedirectURL        string
	SendOobCodeURL     string
	SignInWithEmailURL string
	RefreshTokenURL    string
}

func New(webapikey string, credentials string, redirect string) (Provider, error) {
	fmt.Println(credentials, webapikey)
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
		oauthStateString:   randfuncs.RandomString(20, randfuncs.NewSource()),
		Client:             client,
		WebApiKey:          webapikey,
		RedirectURL:        redirect,
		SendOobCodeURL:     "https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key=",
		SignInWithEmailURL: "https://identitytoolkit.googleapis.com/v1/accounts:signInWithEmailLink?key=",
		RefreshTokenURL:    "https://securetoken.googleapis.com/v1/token?key=",
		name:               "firebase",
	}, nil
}

func (p Provider) BeginAuthFlow(w http.ResponseWriter, r *http.Request) error {
	form := url.Values{}
	form.Add("requestType", "EMAIL_SIGNIN")
	form.Add("email", r.FormValue("email"))
	form.Add("continueUrl", p.RedirectURL)
	req, err := http.NewRequest("POST", p.SendOobCodeURL+p.WebApiKey, strings.NewReader(form.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	if err != nil {
		return err
	}

	_, err = http.DefaultClient.Do(req)
	if err != nil {
		return err
	}

	c := &http.Cookie{
		Name:     "email",
		Value:    r.FormValue("email"),
		Path:     "/",
		HttpOnly: true,
	}

	http.SetCookie(w, c)

	return nil
}

func (p Provider) CompleteAuthFlow(w http.ResponseWriter, r *http.Request) error {
	tokens := &provider.Tokens{}
	c, err := r.Cookie("email")
	if err != nil {
		return err
	}

	oobCode := r.URL.Query().Get("oobCode")

	form := url.Values{}
	form.Add("oobCode", oobCode)
	form.Add("email", c.Value)
	req, err := http.NewRequest("POST", p.SignInWithEmailURL+p.WebApiKey, strings.NewReader(form.Encode()))
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
	if len(tokens.RefreshToken) == 0 || len(tokens.Token) == 0 {
		return fmt.Errorf("tokens is empty")
	}
	Token := http.Cookie{Name: "Token", Value: tokens.Token, MaxAge: 3600, HttpOnly: true, Secure: true}
	RefreshToken := http.Cookie{Name: "RefreshToken", Value: tokens.RefreshToken, HttpOnly: true, Secure: true}
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

	err = resp.Write(w)
	if err != nil {
		return err
	}
	return nil
}
