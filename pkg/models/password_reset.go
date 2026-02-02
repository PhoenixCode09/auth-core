package models

import "time"

// PasswordReset representa una solicitud de reinicio de contraseña.
type PasswordReset struct {
	ID        string    `json:"id" gorm:"primaryKey;type:uuid"`
	UserID    string    `json:"user_id" gorm:"index;not null"`
	TokenHash string    `json:"token_hash" gorm:"not null"`
	ExpiresAt time.Time `json:"expires_at"`
	Used      bool      `json:"used" gorm:"default:false"`
	CreatedAt time.Time `json:"created_at"`
}
