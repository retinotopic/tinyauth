package firebase

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
	"google.golang.org/api/option"
)

type Provider struct {
	name               string
	Client             *auth.Client
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
		w.WriteHeader(http.StatusBadRequest)
		return err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return err
	}
	data := make(map[string]interface{})
	err = json.NewDecoder(resp.Body).Decode(&data)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return err
	}
	_, ok := data["email"]
	if !ok {
		return fmt.Errorf("firebase error")
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

func (p Provider) CompleteAuthFlow(w http.ResponseWriter, r *http.Request) (provider.Tokens, error) {
	tokens := provider.Tokens{}
	c, err := r.Cookie("email")
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return tokens, err
	}
	oobCode := r.URL.Query().Get("oobCode")

	form := url.Values{}
	form.Add("oobCode", oobCode)
	form.Add("email", c.Value)
	req, err := http.NewRequest("POST", p.SignInWithEmailURL+p.WebApiKey, strings.NewReader(form.Encode()))
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
	if len(tokens.RefreshToken) == 0 || len(tokens.Token) == 0 {
		w.WriteHeader(http.StatusBadRequest)
		return tokens, fmt.Errorf("tokens is empty")
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
	w.WriteHeader(http.StatusOK)

	return tokens, err
}
