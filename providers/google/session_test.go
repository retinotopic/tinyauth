package google_test

import (
	"fmt"
	"net/http"
	"os"
	"testing"

	"net/http/httptest"

	"github.com/retinotopic/TinyAuth/providers/google"
)

func TestSession(t *testing.T) {

	p, err := google.New(os.Getenv("GOOGLE_CLIENT_ID"), os.Getenv("GOOGLE_CLIENT_SECRET"), os.Getenv("REDIRECT"))
	if err != nil {
		t.Fatalf("creating provider error: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	c := &http.Cookie{Name: "RefreshToken", Value: os.Getenv("REFRESH_TOKEN")}
	req.AddCookie(c)
	tokens, err := p.Refresh(w, req)
	if err != nil {
		t.Fatalf("creating providing error: %v", err)
	}
	fmt.Println(tokens)
}
