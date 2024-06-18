package google

import (
	"crypto/rsa"
	"errors"
	"net/http"

	"github.com/lestrrat-go/jwx/jwk"
)

func GetPublicKey() (*rsa.PublicKey, error) {
	req, err := http.NewRequest("GET", "https://www.googleapis.com/oauth2/v2/certs", nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	set, err := jwk.ParseReader(resp.Body)
	if err != nil {
		return nil, err
	}
	key, ok := set.Get(1)
	if !ok {
		return nil, errors.New("index is out of range")
	}
	pkey := &rsa.PublicKey{}
	err = key.Raw(pkey)
	if err != nil {
		return nil, err
	}
	return pkey, nil
}
