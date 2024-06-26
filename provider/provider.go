package provider

import (
	"net/http"
)

type Tokens struct {
	Token        string `json:"token"`
	RefreshToken string `json:"refresh_token"`
}

var MapProvider map[string]Provider

type Provider interface {
	BeginAuth(w http.ResponseWriter, r *http.Request) error
	CompleteAuth(w http.ResponseWriter, r *http.Request) (Tokens, error)
	FetchUser(w http.ResponseWriter, r *http.Request) (string, error)
	Refresh(w http.ResponseWriter, r *http.Request) (Tokens, error)
	RevokeRefresh(w http.ResponseWriter, r *http.Request) error
}
