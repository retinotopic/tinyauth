package session

import "net/http"

type Session map[string]Provider

type Provider interface {
	BeginLoginCreate(w http.ResponseWriter, r *http.Request)
	CompleteLoginCreate(w http.ResponseWriter, r *http.Request)
	FetchUser(w http.ResponseWriter, r *http.Request)
	Revoke(w http.ResponseWriter, r *http.Request)
	Refresh(w http.ResponseWriter, r *http.Request)
}

func (p Session) Refresh(w http.ResponseWriter, r *http.Request) {
	p[r.PathValue("provider")].Refresh(w, r)
}
func (p Session) Revoke(w http.ResponseWriter, r *http.Request) {
	p[r.PathValue("provider")].Revoke(w, r)
}
func (p Session) Fetcher(w http.ResponseWriter, r *http.Request) {
	p[r.PathValue("provider")].FetchUser(w, r)
}
func (p Session) BeginLoginCreate(w http.ResponseWriter, r *http.Request) {
	p[r.PathValue("provider")].BeginLoginCreate(w, r)
}
func (p Session) CompleteLoginCreate(w http.ResponseWriter, r *http.Request) {
	p[r.PathValue("provider")].CompleteLoginCreate(w, r)
}
