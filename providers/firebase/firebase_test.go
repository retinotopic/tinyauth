package firebase_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/retinotopic/tinyauth/provider"
	"github.com/retinotopic/tinyauth/providers/firebase"
	"github.com/stretchr/testify/require"
)

func TestFirebase(t *testing.T) {
	ch := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	p, err := firebase.New(ctx, os.Getenv("WEB_API_KEY"), os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"), os.Getenv("REDIRECT"), "/refresh")
	if err != nil {
		t.Fatalf("creating providing error: %v", err)
	}
	r := require.New(t)
	r.Implements((*provider.Provider)(nil), p)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	req.Form = url.Values{}
	req.Form.Add("email", os.Getenv("EMAIL"))
	err = p.BeginAuth(w, req.WithContext(ctx))
	if err != nil {
		t.Fatalf("BeginAuthFlow returned an error: %v", err)
	}
	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/completeauth", func(w http.ResponseWriter, r *http.Request) {
			c := &http.Cookie{Name: "email", Value: os.Getenv("email")}
			r.AddCookie(c)
			_, err := p.CompleteAuth(w, r)
			ch <- err
		})
		http.ListenAndServe(":8080", mux)
	}()
	err = <-ch
	if err != nil {
		t.Fatalf("error completing auth flow: %v", err)
	}
}
