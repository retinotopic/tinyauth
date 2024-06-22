package google

import (
	"crypto/rsa"
	"errors"
	"net/http"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/pascaldekloe/jwt"
)

func GetPublicKey(index int) (*rsa.PublicKey, error) {
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
	key, ok := set.Get(index)
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
func VerifyToken(tokenValue []byte, currentKey *rsa.PublicKey) (*jwt.Claims, error) {
	if claims, err := jwt.RSACheck(tokenValue, currentKey); err == nil {
		return claims, nil
	}

	for i := 0; i < 2; i++ {
		newKey, err := GetPublicKey(i)
		if err != nil {
			continue
		}

		if claims, err := jwt.RSACheck(tokenValue, newKey); err == nil {
			*currentKey = *newKey
			return claims, nil
		}
	}

	return nil, errors.New("failed to verify token with all available keys")
}
