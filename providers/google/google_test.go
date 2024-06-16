package google_test

import (
	"fmt"
	"net/http"
	"os"
	"testing"

	"net/http/httptest"

	"github.com/retinotopic/TinyAuth/providers/google"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func TestGoogle(t *testing.T) {

	p, err := google.New(os.Getenv("GOOGLE_CLIENT_ID"), os.Getenv("GOOGLE_CLIENT_SECRET"), os.Getenv("REDIRECT"))
	if err != nil {
		t.Fatalf("creating provider error: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	err = p.BeginAuthFlow(w, req)
	if err != nil {
		t.Fatalf("BeginAuthFlow returned an error: %v", err)
	}
	resp := w.Result()
	if resp.StatusCode != http.StatusTemporaryRedirect {
		t.Errorf("expected status %d, got %d", http.StatusTemporaryRedirect, resp.StatusCode)
	}

	location, err := resp.Location()
	if err != nil {
		t.Fatalf("failed to get redirect location: %v", err)
	}
	expectedURL := p.Config.AuthCodeURL(p.OauthStateString, oauth2.AccessTypeOffline)
	if location.String() != expectedURL {
		t.Errorf("expected redirect to %s, got %s", expectedURL, location.String())
	}
	r := require.New(t)
	r.NoError(err)
	r.Contains(location.String(), fmt.Sprintf("client_id=%s", os.Getenv("GOOGLE_CLIENT_ID")))
	r.Contains(location.String(), fmt.Sprintf("state=%s", p.OauthStateString))
	r.Contains(location.String(), "accounts.google.com/o/oauth2/auth")
	r.Contains(location.String(), "scope=email")
	r.Contains(location.String(), "access_type=offline")
}
