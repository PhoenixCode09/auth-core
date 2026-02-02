package models

import "time"

// AuthCode representa un código de autorización temporal (PKCE support).
type AuthCode struct {
	ID                  string    `json:"id" gorm:"primaryKey;type:uuid"`
	Code                string    `json:"code" gorm:"index;not null"`
	ClientID            string    `json:"client_id" gorm:"index;not null"`
	UserID              string    `json:"user_id" gorm:"index;not null"`
	RedirectURI         string    `json:"redirect_uri"`
	CodeChallenge       string    `json:"code_challenge"`
	CodeChallengeMethod string    `json:"code_challenge_method"`
	ExpiresAt           time.Time `json:"expires_at"`
	Used                bool      `json:"used" gorm:"default:false"`
	CreatedAt           time.Time `json:"created_at"`
}
