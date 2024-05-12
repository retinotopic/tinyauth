package provider

import (
	"errors"
	"net/http"
	"strings"
)

type Tokens struct {
	Token        string `json:"Token"`
	RefreshToken string `json:"RefreshToken"`
}

type ProviderInfo struct {
	mapProvider map[string]Provider
}
type Provider interface {
	BeginAuthFlow(w http.ResponseWriter, r *http.Request) error
	CompleteAuthFlow(w http.ResponseWriter, r *http.Request) error
	FetchUser(w http.ResponseWriter, r *http.Request) (string, error)
	RevokeRefresh(w http.ResponseWriter, r *http.Request) error
	Refresh(w http.ResponseWriter, r *http.Request) error
	GetName() string
}

func (p ProviderInfo) Refresh(w http.ResponseWriter, r *http.Request) error {
	RawToken, err := r.Cookie("RefreshToken")
	if err != nil {
		return err
	}
	prvdr, token, ok := strings.Cut(RawToken.Value, ".")
	if !ok {
		return errors.New("malformed token")
	}
	r.Header.Del("Cookie")
	RawToken.Value = token
	r.AddCookie(RawToken)
	if prvdr, ok := p.mapProvider[prvdr]; ok {
		return prvdr.Refresh(w, r)
	}
	return errors.New("no such provider")
}
func (p ProviderInfo) RevokeRefresh(w http.ResponseWriter, r *http.Request) error {
	RawToken, err := r.Cookie("RefreshToken")
	if err != nil {
		return err
	}
	prvdr, token, ok := strings.Cut(RawToken.Value, ".")
	if !ok {
		return errors.New("malformed token")
	}
	r.Header.Del("Cookie")
	RawToken.Value = token
	r.AddCookie(RawToken)
	if prvdr, ok := p.mapProvider[prvdr]; ok {
		return prvdr.RevokeRefresh(w, r)
	}
	return errors.New("no such provider")
}
func (p ProviderInfo) FetchUser(w http.ResponseWriter, r *http.Request) (string, error) {
	RawToken, err := r.Cookie("RefreshToken")
	if err != nil {
		return "", err
	}
	prvdr, token, ok := strings.Cut(RawToken.Value, ".")
	if !ok {
		return "", errors.New("malformed token")
	}
	r.Header.Del("Cookie")
	RawToken.Value = token
	r.AddCookie(RawToken)
	if prvdr, ok := p.mapProvider[prvdr]; ok {
		return prvdr.FetchUser(w, r)
	}
	return "", errors.New("no such provider")
}
