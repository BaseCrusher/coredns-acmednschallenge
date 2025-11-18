package acmednschallenge

import (
	"crypto"

	"github.com/go-acme/lego/v4/registration"
)

type AcmeUser struct {
	Email        string                 `json:"email"`
	Registration *registration.Resource `json:"-"` // ignored
	Key          crypto.PrivateKey      `json:"key"`
}

func (u *AcmeUser) GetEmail() string {
	return u.Email
}
func (u *AcmeUser) GetRegistration() *registration.Resource {
	return u.Registration
}
func (u *AcmeUser) GetPrivateKey() crypto.PrivateKey {
	return u.Key
}
