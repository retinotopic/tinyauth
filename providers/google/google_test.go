package google_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/retinotopic/TinyAuth/provider"
	"github.com/retinotopic/TinyAuth/providers/google"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func TestGoogle(t *testing.T) {
	p, err := google.New(os.Getenv("GOOGLE_CLIENT_ID"), os.Getenv("GOOGLE_CLIENT_SECRET"), os.Getenv("REDIRECT"))
	if err != nil {
		t.Fatalf("creating provider error: %v", err)
	}
	r := require.New(t)
	r.Implements((*provider.Provider)(nil), p)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	err = p.BeginAuth(w, req)
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
	r.NoError(err)
	r.Contains(location.String(), fmt.Sprintf("client_id=%s", os.Getenv("GOOGLE_CLIENT_ID")))
	r.Contains(location.String(), fmt.Sprintf("state=%s", p.OauthStateString))
	r.Contains(location.String(), "accounts.google.com/o/oauth2/auth")
	r.Contains(location.String(), "scope=openid")
	r.Contains(location.String(), "access_type=offline")

	/* You can test it manually if you add -v flag and uncomment this part of the code (the link obtained from t.Log(expectedURL) enter it into the browser)
	and change the redirect to your own
	ch := make(chan error, 1)
	t.Log(expectedURL)

	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/completeauth", func(w http.ResponseWriter, r *http.Request) {
			_, err := p.CompleteAuth(w, r)
			ch <- err
		})
		http.ListenAndServe(":8080", mux)
	}()
	err = <-ch
	if err != nil {
		t.Fatalf("error completing auth flow: %v", err)
	}
	*/
}
