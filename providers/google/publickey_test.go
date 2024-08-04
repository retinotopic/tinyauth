package google_test

import (
	"context"
	"crypto/rsa"
	"net/http"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/jwk"
)

func TestGetPublicKey(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, err := http.NewRequest("GET", "https://www.googleapis.com/oauth2/v2/certs", nil)
	if err != nil {
		t.Fatalf("creating request error: %v", err)
	}
	resp, err := http.DefaultClient.Do(req.WithContext(ctx))
	if err != nil {
		t.Fatalf("http request error: %v", err)
	}
	set, err := jwk.ParseReader(resp.Body)
	if err != nil {
		t.Fatalf("parsing JWK set error: %v", err)
	}
	key, ok := set.Get(1)
	if !ok {
		t.Fatalf("index is out of range")
	}
	pkey := &rsa.PublicKey{}
	err = key.Raw(pkey)
	if err != nil {
		t.Fatalf("creating raw key error: %v", err)
	}
	if pkey.N == nil {
		t.Fatalf("public key is empty")
	}
}
