package firebase_test

import (
	"net/http"
	"net/url"
	"os"
	"testing"

	"net/http/httptest"

	"github.com/retinotopic/TinyAuth/providers/firebase"
)

func TestFirebase(t *testing.T) {

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

}
