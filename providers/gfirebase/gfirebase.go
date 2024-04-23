package gfirebase

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	firebase "firebase.google.com/go/v4"
	"firebase.google.com/go/v4/auth"
	"github.com/retinotopic/pokerGO/pkg/randfuncs"
	"google.golang.org/api/option"
)

type Provider struct {
	Client             *auth.Client
	oauthStateString   string
	WebApiKey          string
	RedirectURL        string
	SendOobCodeURL     string
	SignInWithEmailURL string
	RefreshTokenURL    string
}

func New(webapikey string, credentials string, redirect string) Provider {
	fmt.Println(credentials, webapikey)
	opt := option.WithCredentialsFile(credentials)
	app, err := firebase.NewApp(context.Background(), nil, opt)
	if err != nil {
		log.Fatalf("error initializing app: %v\n", err)
	}
	client, err := app.Auth(context.Background())
	if err != nil {
		log.Fatalf("error initializing auth client: %v\n", err)
	}
	fmt.Println("vse ok")
	return Provider{
		oauthStateString:   randfuncs.RandomString(20, randfuncs.NewSource()),
		Client:             client,
		WebApiKey:          webapikey,
		RedirectURL:        redirect,
		SendOobCodeURL:     "https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key=",
		SignInWithEmailURL: "https://identitytoolkit.googleapis.com/v1/accounts:signInWithEmailLink?key=",
		RefreshTokenURL:    "https://securetoken.googleapis.com/v1/token?key=",
	}
}
func (p Provider) BeginLoginCreate(w http.ResponseWriter, r *http.Request) {
	form := url.Values{}
	form.Add("requestType", "EMAIL_SIGNIN")
	form.Add("email", r.FormValue("email"))
	form.Add("continueUrl", p.RedirectURL)
	req, err := http.NewRequest("POST", p.SendOobCodeURL+p.WebApiKey, strings.NewReader(form.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	if err != nil {
		log.Println(err, "creating request error")
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Println(err, "request error")
	}

	c := &http.Cookie{
		Name:     "email",
		Value:    r.FormValue("email"),
		Path:     "/",
		HttpOnly: true,
	}

	http.SetCookie(w, c)
	w.WriteHeader(http.StatusOK)
	err = resp.Write(w)
	if err != nil {
		log.Println(err, "write error")
	}

}

func (p Provider) CompleteLoginCreate(w http.ResponseWriter, r *http.Request) {
	tokens := make(map[string]string)
	c, err := r.Cookie("email")
	if err != nil {
		log.Println(err, "cookie retrieve error")
	}

	oobCode := r.URL.Query().Get("oobCode")

	form := url.Values{}
	form.Add("oobCode", oobCode)
	form.Add("email", c.Value)
	req, err := http.NewRequest("POST", p.SignInWithEmailURL+p.WebApiKey, strings.NewReader(form.Encode()))
	if err != nil {
		log.Println(err, "creating request error")
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Println(err, "request error")
	}
	err = json.NewDecoder(resp.Body).Decode(&tokens)
	if err != nil {
		log.Println(err, "json decode error")
	}

	idToken := http.Cookie{Name: "idToken", Value: tokens["IdToken"], MaxAge: 3600, Path: "/", HttpOnly: true, Secure: true}
	refreshToken := http.Cookie{Name: "refreshToken", Value: tokens["RefreshToken"], Path: "/refresh", HttpOnly: true, Secure: true}
	providerC := http.Cookie{Name: "provider", Value: "gfirebase", Path: "/", HttpOnly: true, Secure: true}
	http.SetCookie(w, &idToken)
	http.SetCookie(w, &refreshToken)
	http.SetCookie(w, &providerC)
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
		log.Println(err, "write error")
	}

}
