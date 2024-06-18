package firebase_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/retinotopic/TinyAuth/providers/firebase"
)

func TestSession(t *testing.T) {
	fmt.Println(os.Getenv("REFRESH_TOKEN"))
	p, err := firebase.New(os.Getenv("WEB_API_KEY"), os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"), os.Getenv("REDIRECT"))
	if err != nil {
		t.Fatalf("creating provider error: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	c := &http.Cookie{Name: "refresh_token", Value: os.Getenv("REFRESH_TOKEN")}
	req.AddCookie(c)
	tokens, err := p.Refresh(w, req)
	if err != nil {
		t.Fatalf("error refreshing token: %v", err)
	}
	fmt.Println(tokens)
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	w = httptest.NewRecorder()
	c = &http.Cookie{Name: "token", Value: tokens.Token}
	req.AddCookie(c)
	c = &http.Cookie{Name: "refresh_token", Value: os.Getenv("REFRESH_TOKEN")}
	req.AddCookie(c)
	sub, err := p.FetchUser(w, req)
	if err != nil {
		t.Fatalf("error fetching subject: %v", err)
	}
	fmt.Println(sub)
	err = p.RevokeRefresh(w, req)
	if err != nil {
		t.Fatalf("error revoking refresh token: %v", err)
	}
}
