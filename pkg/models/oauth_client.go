package models

import "time"

// OAuthClient representa un cliente OAuth/OIDC registrado.
type OAuthClient struct {
	ID           string    `json:"id" gorm:"primaryKey;type:uuid"`
	ClientID     string    `json:"client_id" gorm:"uniqueIndex;not null"`
	ClientSecret string    `json:"client_secret" gorm:"not null"` // store hashed in production
	RedirectURIs string    `json:"redirect_uris"`                 // comma-separated for simplicity
	GrantTypes   string    `json:"grant_types"`                   // comma-separated
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}
