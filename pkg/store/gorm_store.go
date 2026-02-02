package store

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/yourorg/auth-core/pkg/models"
)

// GormStore is a GORM-backed store implementation.
type GormStore struct {
	db *gorm.DB
}

// NewGormStore opens a DB connection based on DSN. If dsn starts with "sqlite" or contains ".db" uses sqlite,
// otherwise tries postgres. autoMigrate runs migrations if true.
func NewGormStore(dsn string, autoMigrate bool) (*GormStore, error) {
	if dsn == "" {
		return nil, fmt.Errorf("dsn is empty")
	}

	var dialector gorm.Dialector
	if strings.HasPrefix(dsn, "sqlite://") || strings.HasSuffix(dsn, ".db") || strings.Contains(dsn, ":memory:") {
		// support sqlite dsn like "sqlite://file.db" or ":memory:"
		path := strings.TrimPrefix(dsn, "sqlite://")
		dialector = sqlite.Open(path)
	} else {
		// assume postgres DSN
		dialector = postgres.Open(dsn)
	}

	db, err := gorm.Open(dialector, &gorm.Config{})
	if err != nil {
		return nil, err
	}

	s := &GormStore{db: db}
	if autoMigrate {
		if err := s.AutoMigrate(); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func (s *GormStore) AutoMigrate() error {
	// Avoid import cycle by referring to models via import path
	// Import models package here to run automigrate
	importModels := []interface{}{
		new(models.User),
		new(models.Role),
		new(models.RefreshToken),
		new(models.PasswordReset),
		new(models.OAuthClient),
		new(models.AuthCode),
	}
	return s.db.AutoMigrate(importModels...)
}

func (s *GormStore) Close() error {
	db, err := s.db.DB()
	if err != nil {
		return err
	}
	return db.Close()
}

// CreateUser crea un usuario. Falla si ya existe email.
func (s *GormStore) CreateUser(ctx context.Context, u *models.User) error {
	if u == nil {
		return errors.New("user is nil")
	}
	return s.db.WithContext(ctx).Create(u).Error
}

func (s *GormStore) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	var u models.User
	if err := s.db.WithContext(ctx).Preload("Roles").Where("email = ?", email).First(&u).Error; err != nil {
		return nil, err
	}
	return &u, nil
}

func (s *GormStore) GetUserByID(ctx context.Context, id string) (*models.User, error) {
	var u models.User
	if err := s.db.WithContext(ctx).Preload("Roles").Where("id = ?", id).First(&u).Error; err != nil {
		return nil, err
	}
	return &u, nil
}

func (s *GormStore) UpdateUser(ctx context.Context, u *models.User) error {
	if u == nil {
		return errors.New("user is nil")
	}
	return s.db.WithContext(ctx).Save(u).Error
}

func (s *GormStore) EnsureRole(ctx context.Context, r *models.Role) error {
	if r == nil {
		return errors.New("role is nil")
	}
	var existing models.Role
	err := s.db.WithContext(ctx).Where("name = ?", r.Name).First(&existing).Error
	if err == nil {
		// exists, update description
		existing.Description = r.Description
		return s.db.WithContext(ctx).Save(&existing).Error
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return s.db.WithContext(ctx).Create(r).Error
	}
	return err
}

func (s *GormStore) AssignRoleToUser(ctx context.Context, userID string, roleName string) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var u models.User
		if err := tx.Preload("Roles").Where("id = ?", userID).First(&u).Error; err != nil {
			return err
		}
		var r models.Role
		if err := tx.Where("name = ?", roleName).First(&r).Error; err != nil {
			return err
		}
		// append role if not exists
		for _, existing := range u.Roles {
			if existing.Name == r.Name {
				return nil
			}
		}
		return tx.Model(&u).Association("Roles").Append(&r)
	})
}

func (s *GormStore) CreateRefreshToken(ctx context.Context, rt *models.RefreshToken) error {
	if rt == nil {
		return errors.New("refresh token is nil")
	}
	return s.db.WithContext(ctx).Create(rt).Error
}

func (s *GormStore) GetRefreshTokenByHash(ctx context.Context, hash string) (*models.RefreshToken, error) {
	var rt models.RefreshToken
	if err := s.db.WithContext(ctx).Where("token_hash = ?", hash).First(&rt).Error; err != nil {
		return nil, err
	}
	return &rt, nil
}

func (s *GormStore) RevokeRefreshToken(ctx context.Context, id string) error {
	return s.db.WithContext(ctx).Model(&models.RefreshToken{}).Where("id = ?", id).Update("revoked", true).Error
}

func (s *GormStore) RevokeAllRefreshTokensForUser(ctx context.Context, userID string) error {
	return s.db.WithContext(ctx).Model(&models.RefreshToken{}).Where("user_id = ?", userID).Update("revoked", true).Error
}

func (s *GormStore) CreatePasswordReset(ctx context.Context, pr *models.PasswordReset) error {
	if pr == nil {
		return errors.New("password reset is nil")
	}
	return s.db.WithContext(ctx).Create(pr).Error
}

func (s *GormStore) GetPasswordResetByHash(ctx context.Context, hash string) (*models.PasswordReset, error) {
	var pr models.PasswordReset
	if err := s.db.WithContext(ctx).Where("token_hash = ?", hash).First(&pr).Error; err != nil {
		return nil, err
	}
	return &pr, nil
}

func (s *GormStore) MarkPasswordResetUsed(ctx context.Context, id string) error {
	return s.db.WithContext(ctx).Model(&models.PasswordReset{}).Where("id = ?", id).Update("used", true).Error
}

func (s *GormStore) CreateOAuthClient(ctx context.Context, c *models.OAuthClient) error {
	if c == nil {
		return errors.New("oauth client is nil")
	}
	return s.db.WithContext(ctx).Create(c).Error
}

func (s *GormStore) GetOAuthClientByClientID(ctx context.Context, clientID string) (*models.OAuthClient, error) {
	var c models.OAuthClient
	if err := s.db.WithContext(ctx).Where("client_id = ?", clientID).First(&c).Error; err != nil {
		return nil, err
	}
	return &c, nil
}

func (s *GormStore) CreateAuthCode(ctx context.Context, code *models.AuthCode) error {
	if code == nil {
		return errors.New("auth code is nil")
	}
	return s.db.WithContext(ctx).Create(code).Error
}

func (s *GormStore) GetAuthCode(ctx context.Context, code string) (*models.AuthCode, error) {
	var ac models.AuthCode
	if err := s.db.WithContext(ctx).Where("code = ?", code).First(&ac).Error; err != nil {
		return nil, err
	}
	return &ac, nil
}

func (s *GormStore) MarkAuthCodeUsed(ctx context.Context, id string) error {
	return s.db.WithContext(ctx).Model(&models.AuthCode{}).Where("id = ?", id).Update("used", true).Error
}
