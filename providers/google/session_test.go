package google_test

import (
	"net/http"
	"os"
	"testing"

	"net/http/httptest"

	"github.com/retinotopic/tinyauth/providers/google"
)

func TestSession(t *testing.T) {
	p, err := google.New(os.Getenv("GOOGLE_CLIENT_ID"), os.Getenv("GOOGLE_CLIENT_SECRET"), os.Getenv("REDIRECT"), "/refresh")
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
	_, err = p.VerifyToken([]byte(tokens.Token))
	if err != nil {
		t.Fatalf("error verifying token: %v", err)
	}
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	w = httptest.NewRecorder()
	c = &http.Cookie{Name: "token", Value: tokens.Token}
	req.AddCookie(c)
	c = &http.Cookie{Name: "refresh_token", Value: os.Getenv("REFRESH_TOKEN")}
	req.AddCookie(c)
	_, err = p.FetchUser(w, req)
	if err != nil {
		t.Fatalf("error fetching subject: %v", err)
	}
	err = p.RevokeRefresh(w, req)
	if err != nil {
		t.Fatalf("error revoking refresh token: %v", err)
	}
}
