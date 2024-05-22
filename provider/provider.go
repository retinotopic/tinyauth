package provider

import (
	"net/http"
)

type Tokens struct {
	Token        string `json:"Token"`
	RefreshToken string `json:"RefreshToken"`
}

var MapProvider map[string]Provider

type Provider interface {
	BeginAuthFlow(w http.ResponseWriter, r *http.Request) error
	CompleteAuthFlow(w http.ResponseWriter, r *http.Request) error
	FetchUser(w http.ResponseWriter, r *http.Request) (string, error)
	RevokeRefresh(w http.ResponseWriter, r *http.Request) error
	Refresh(w http.ResponseWriter, r *http.Request) error
}
