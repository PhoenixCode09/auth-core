package models

import "time"

// RefreshToken representa un token de refresco almacenado en la DB.
type RefreshToken struct {
	ID        string    `json:"id" gorm:"primaryKey;type:uuid"`
	UserID    string    `json:"user_id" gorm:"index;not null"`
	TokenHash string    `json:"token_hash" gorm:"not null"`
	ExpiresAt time.Time `json:"expires_at"`
	Revoked   bool      `json:"revoked" gorm:"default:false"`
	CreatedAt time.Time `json:"created_at"`
}
