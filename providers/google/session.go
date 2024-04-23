package google

import (
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pascaldekloe/jwt"
	"github.com/retinotopic/GoChat/pkg/safectx"
	"golang.org/x/oauth2/google"
)

func (p Provider) Refresh(w http.ResponseWriter, r *http.Request) {
	tokens := make(map[string]string)
	form := url.Values{}
	token, err := r.Cookie("refreshToken")
	if err != nil {
		log.Println(err, "revoke cookie retrieve err")
	}
	form.Add("refresh_token", token.Value)
	form.Add("grant_type", "refresh_token")
	form.Add("client_id", p.Config.ClientID)
	form.Add("client_secret", p.Config.ClientSecret)
	req, err := http.NewRequest("POST", google.Endpoint.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		log.Println(err, "error creating request error")
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Println(err, "error request error")
	}
	err = json.NewDecoder(resp.Body).Decode(&tokens)
	if err != nil {
		log.Println(err, "json decode error")
	}

	idToken := http.Cookie{Name: "idToken", Value: tokens["IdToken"], MaxAge: 3600, Path: "/", HttpOnly: true, Secure: true}
	refreshToken := http.Cookie{Name: "refreshToken", Value: tokens["RefreshToken"], Path: "/refresh", HttpOnly: true, Secure: true}
	http.SetCookie(w, &idToken)
	http.SetCookie(w, &refreshToken)

	log.Println(resp.StatusCode)

}
func (p Provider) Revoke(w http.ResponseWriter, r *http.Request) {
	form := url.Values{}
	token, err := r.Cookie("refreshToken")
	if err != nil {
		log.Println(err, "revoke cookie retrieve err")
	}
	form.Add("token", token.Value)
	req, err := http.NewRequest("POST", p.RevokeURL, strings.NewReader(form.Encode()))
	if err != nil {
		log.Println(err, "error request error")
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Println(err, "error request error")
	}
	///
	log.Println(resp.StatusCode)

}
func (p Provider) FetchUser(w http.ResponseWriter, r *http.Request) {
	token, err3 := r.Cookie("token")
	if err3 != nil {
		w.WriteHeader(http.StatusUnauthorized)
	}
	claims, err4 := jwt.RSACheck([]byte(token.Value), p.PublicKey)
	if err4 != nil {
		w.WriteHeader(http.StatusBadRequest)
	}
	if !claims.Valid(time.Now()) {
		w.WriteHeader(http.StatusBadRequest)
	}
	/*ctx := r.Context()
	ctx = context.WithValue(ctx, "user", claims.Subject)
	r = r.WithContext(ctx)*/
	ctx := safectx.SetContext(r.Context(), "sub", claims.Subject)
	*r = *(r.WithContext(ctx))
}
