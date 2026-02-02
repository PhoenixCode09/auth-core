package models

import "time"

// User representa a un usuario del sistema.
type User struct {
	ID        string    `json:"id" gorm:"primaryKey;type:uuid"`
	Email     string    `json:"email" gorm:"uniqueIndex;not null"`
	Username  string    `json:"username,omitempty" gorm:"index"`
	Password  []byte    `json:"-"`
	Salt      []byte    `json:"-"`
	IsActive  bool      `json:"is_active" gorm:"default:true"`
	Roles     []Role    `json:"roles,omitempty" gorm:"many2many:user_roles;constraint:OnUpdate:CASCADE,OnDelete:SET NULL;"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}
