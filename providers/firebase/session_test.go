package firebase_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/retinotopic/tinyauth/providers/firebase"
)

func TestSession(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	p, err := firebase.New(ctx, os.Getenv("WEB_API_KEY"), os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"), os.Getenv("REDIRECT"), "/refresh")
	if err != nil {
		t.Fatalf("creating provider error: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	c := &http.Cookie{Name: "refresh_token", Value: os.Getenv("REFRESH_TOKEN")}
	req.AddCookie(c)
	tokens, err := p.Refresh(w, req.WithContext(ctx))
	if err != nil {
		t.Fatalf("error refreshing token: %v", err)
	}
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	w = httptest.NewRecorder()
	c = &http.Cookie{Name: "token", Value: tokens.Token}
	req.AddCookie(c)
	c = &http.Cookie{Name: "refresh_token", Value: os.Getenv("REFRESH_TOKEN")}
	req.AddCookie(c)
	_, err = p.FetchUser(w, req.WithContext(ctx))
	if err != nil {
		t.Fatalf("error fetching subject: %v", err)
	}
	err = p.RevokeRefresh(w, req.WithContext(ctx))
	if err != nil {
		t.Fatalf("error revoking refresh token: %v", err)
	}
}
