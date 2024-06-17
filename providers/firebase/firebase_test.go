package firebase_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"

	"github.com/retinotopic/TinyAuth/providers/firebase"
)

func TestFirebase(t *testing.T) {
	ch := make(chan error, 1)
	p, err := firebase.New(os.Getenv("WEB_API_KEY"), os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"), os.Getenv("REDIRECT"))
	if err != nil {
		t.Fatalf("creating providing error: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	req.Form = url.Values{}
	req.Form.Add("email", os.Getenv("EMAIL"))
	err = p.BeginAuthFlow(w, req)
	if err != nil {
		t.Fatalf("BeginAuthFlow returned an error: %v", err)
	}
	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/CompleteAuth", func(w http.ResponseWriter, r *http.Request) {
			c := &http.Cookie{Name: "email", Value: os.Getenv("email")}
			r.AddCookie(c)
			_, err := p.CompleteAuthFlow(w, r)
			ch <- err
		})
		http.ListenAndServe(":8080", mux)
	}()
	for err = range ch {
		if err != nil {
			t.Fatalf("error completing auth flow: %v", err)
		}
	}
}
