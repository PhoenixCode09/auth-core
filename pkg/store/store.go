package store

import (
	"context"

	"github.com/yourorg/auth-core/pkg/models"
)

// Store is the persistence interface used by auth-core.
// Implementations may use GORM, ent, or raw SQL.
type Store interface {
	AutoMigrate() error
	Close() error

	// Users
	CreateUser(ctx context.Context, u *models.User) error
	GetUserByEmail(ctx context.Context, email string) (*models.User, error)
	GetUserByID(ctx context.Context, id string) (*models.User, error)
	UpdateUser(ctx context.Context, u *models.User) error

	// Roles
	EnsureRole(ctx context.Context, r *models.Role) error
	AssignRoleToUser(ctx context.Context, userID string, roleName string) error

	// Refresh tokens
	CreateRefreshToken(ctx context.Context, rt *models.RefreshToken) error
	GetRefreshTokenByHash(ctx context.Context, hash string) (*models.RefreshToken, error)
	RevokeRefreshToken(ctx context.Context, id string) error
	RevokeAllRefreshTokensForUser(ctx context.Context, userID string) error

	// Password resets
	CreatePasswordReset(ctx context.Context, pr *models.PasswordReset) error
	GetPasswordResetByHash(ctx context.Context, hash string) (*models.PasswordReset, error)
	MarkPasswordResetUsed(ctx context.Context, id string) error

	// OAuth clients
	CreateOAuthClient(ctx context.Context, c *models.OAuthClient) error
	GetOAuthClientByClientID(ctx context.Context, clientID string) (*models.OAuthClient, error)

	// Auth codes
	CreateAuthCode(ctx context.Context, code *models.AuthCode) error
	GetAuthCode(ctx context.Context, code string) (*models.AuthCode, error)
	MarkAuthCodeUsed(ctx context.Context, id string) error
}
