package auth

import (
	"context"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"math/big"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/yourorg/auth-core/pkg/crypto"
	"github.com/yourorg/auth-core/pkg/models"
	"github.com/yourorg/auth-core/pkg/store"
)

// Config holds configuration for the auth service.
type Config struct {
	JWTExpiry     time.Duration
	RefreshExpiry time.Duration
	Issuer        string
}

// Service is the core auth service.
type Service struct {
	cfg   Config
	store store.Store
	kp    crypto.KeyProvider
	priv  *rsa.PrivateKey
	pub   *rsa.PublicKey
}

// NewService crea un Service y carga las claves RSA desde el KeyProvider.
func NewService(cfg Config, st store.Store, kp crypto.KeyProvider) (*Service, error) {
	privPem, err := kp.GetPrivateKeyPEM()
	if err != nil {
		return nil, err
	}
	priv, err := crypto.ParsePrivateKey(privPem)
	if err != nil {
		return nil, err
	}
	pubPem, err := kp.GetPublicKeyPEM()
	if err != nil {
		return nil, err
	}
	pub, err := crypto.ParsePublicKey(pubPem)
	if err != nil {
		return nil, err
	}
	return &Service{cfg: cfg, store: st, kp: kp, priv: priv, pub: pub}, nil
}

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrInactiveUser       = errors.New("user inactive")
)

// Register crea un usuario y almacena el hash cifrado.
func (s *Service) Register(ctx context.Context, email, username, password string) (*models.User, error) {
	// check existing
	if u, _ := s.store.GetUserByEmail(ctx, email); u != nil {
		return nil, errors.New("user already exists")
	}

	salt, encHash, err := crypto.HashPassword(password, s.kp)
	if err != nil {
		return nil, err
	}
	user := &models.User{
		ID:       uuid.NewString(),
		Email:    email,
		Username: username,
		Password: encHash,
		Salt:     salt,
		IsActive: true,
	}
	if err := s.store.CreateUser(ctx, user); err != nil {
		return nil, err
	}
	// ensure default role 'user'
	r := &models.Role{Name: "user", Description: "default user"}
	s.store.EnsureRole(ctx, r)
	s.store.AssignRoleToUser(ctx, user.ID, "user")
	return user, nil
}

// Login verifica credenciales y retorna access+refresh tokens.
func (s *Service) Login(ctx context.Context, email, password string) (accessToken string, refreshToken string, err error) {
	u, err := s.store.GetUserByEmail(ctx, email)
	if err != nil {
		return "", "", ErrInvalidCredentials
	}
	if !u.IsActive {
		return "", "", ErrInactiveUser
	}
	ok, err := crypto.VerifyPassword(password, u.Salt, u.Password, s.kp)
	if err != nil || !ok {
		return "", "", ErrInvalidCredentials
	}
	// Issue tokens
	access, refresh, err := s.IssueTokens(ctx, u)
	if err != nil {
		return "", "", err
	}
	return access, refresh, nil
}

// IssueTokens crea un JWT firmado (RS256) y un refresh token opaco (UUID) que almacena su hash.
func (s *Service) IssueTokens(ctx context.Context, u *models.User) (accessToken string, refreshToken string, err error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"iss":   s.cfg.Issuer,
		"sub":   u.ID,
		"iat":   now.Unix(),
		"exp":   now.Add(s.cfg.JWTExpiry).Unix(),
		"roles": extractRoleNames(u.Roles),
		"jti":   uuid.NewString(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signed, err := token.SignedString(s.priv)
	if err != nil {
		return "", "", err
	}
	// create refresh token
	rt := uuid.NewString()
	h := sha256.Sum256([]byte(rt))
	hStr := hex.EncodeToString(h[:])
	rtModel := &models.RefreshToken{
		ID:        uuid.NewString(),
		UserID:    u.ID,
		TokenHash: hStr,
		ExpiresAt: time.Now().Add(s.cfg.RefreshExpiry),
		Revoked:   false,
	}
	if err := s.store.CreateRefreshToken(ctx, rtModel); err != nil {
		return "", "", err
	}
	return signed, rt, nil
}

// Refresh valida un refresh token (por su hash) y devuelve un nuevo access token y rotated refresh token.
func (s *Service) Refresh(ctx context.Context, refresh string) (newAccess string, newRefresh string, err error) {
	h := sha256.Sum256([]byte(refresh))
	hStr := hex.EncodeToString(h[:])
	rtModel, err := s.store.GetRefreshTokenByHash(ctx, hStr)
	if err != nil {
		return "", "", errors.New("invalid refresh token")
	}
	if rtModel.Revoked || rtModel.ExpiresAt.Before(time.Now()) {
		return "", "", errors.New("refresh token revoked or expired")
	}
	// get user
	u, err := s.store.GetUserByID(ctx, rtModel.UserID)
	if err != nil {
		return "", "", err
	}
	// revoke old
	if err := s.store.RevokeRefreshToken(ctx, rtModel.ID); err != nil {
		return "", "", err
	}
	// issue new pair
	access, refreshNew, err := s.IssueTokens(ctx, u)
	if err != nil {
		return "", "", err
	}
	return access, refreshNew, nil
}

// GetUserByID delega en el store para obtener el usuario.
func (s *Service) GetUserByID(ctx context.Context, id string) (*models.User, error) {
	return s.store.GetUserByID(ctx, id)
}

// Logout revoca el refresh token pasado.
func (s *Service) Logout(ctx context.Context, refresh string) error {
	if refresh == "" {
		return errors.New("empty refresh token")
	}
	h := sha256.Sum256([]byte(refresh))
	hStr := hex.EncodeToString(h[:])
	rt, err := s.store.GetRefreshTokenByHash(ctx, hStr)
	if err != nil {
		return err
	}
	return s.store.RevokeRefreshToken(ctx, rt.ID)
}

// ValidateAccessToken valida el JWT y devuelve el usuario correspondiente.
func (s *Service) ValidateAccessToken(ctx context.Context, tokenStr string) (*models.User, error) {
	if tokenStr == "" {
		return nil, errors.New("empty token")
	}
	tok, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return s.pub, nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok || !tok.Valid {
		return nil, errors.New("invalid token")
	}
	sub, ok := claims["sub"].(string)
	if !ok {
		return nil, errors.New("invalid sub claim")
	}
	return s.store.GetUserByID(ctx, sub)
}

// RequestPasswordReset crea un token de reset (devuelve token claro para demo) y lo persiste hasheado.
func (s *Service) RequestPasswordReset(ctx context.Context, email string) (string, error) {
	u, err := s.store.GetUserByEmail(ctx, email)
	if err != nil {
		// do not leak existence
		return "", nil
	}
	token := uuid.NewString()
	h := sha256.Sum256([]byte(token))
	hStr := hex.EncodeToString(h[:])
	pr := &models.PasswordReset{
		ID:        uuid.NewString(),
		UserID:    u.ID,
		TokenHash: hStr,
		ExpiresAt: time.Now().Add(time.Hour),
		Used:      false,
	}
	if err := s.store.CreatePasswordReset(ctx, pr); err != nil {
		return "", err
	}
	// in production we'd send token via email; for demo return it.
	return token, nil
}

// ConfirmPasswordReset verifica token y actualiza la contraseña, revocando refresh tokens.
func (s *Service) ConfirmPasswordReset(ctx context.Context, token, newPassword string) error {
	h := sha256.Sum256([]byte(token))
	hStr := hex.EncodeToString(h[:])
	pr, err := s.store.GetPasswordResetByHash(ctx, hStr)
	if err != nil {
		return err
	}
	if pr.Used || pr.ExpiresAt.Before(time.Now()) {
		return errors.New("token invalid or expired")
	}
	u, err := s.store.GetUserByID(ctx, pr.UserID)
	if err != nil {
		return err
	}
	// hash new password
	salt, encHash, err := crypto.HashPassword(newPassword, s.kp)
	if err != nil {
		return err
	}
	u.Salt = salt
	u.Password = encHash
	if err := s.store.UpdateUser(ctx, u); err != nil {
		return err
	}
	if err := s.store.MarkPasswordResetUsed(ctx, pr.ID); err != nil {
		return err
	}
	// revoke all refresh tokens
	if err := s.store.RevokeAllRefreshTokensForUser(ctx, u.ID); err != nil {
		return err
	}
	return nil
}

// EnsureRole crea o actualiza un role.
func (s *Service) EnsureRole(ctx context.Context, name, description string) error {
	r := &models.Role{Name: name, Description: description}
	return s.store.EnsureRole(ctx, r)
}

// AssignRoleToUser asgina un role existente a un user.
func (s *Service) AssignRoleToUser(ctx context.Context, userID, roleName string) error {
	return s.store.AssignRoleToUser(ctx, userID, roleName)
}

// Config retorna la configuración actual del servicio.
func (s *Service) Config() Config {
	return s.cfg
}

func extractRoleNames(roles []models.Role) []string {
	n := make([]string, 0, len(roles))
	for _, r := range roles {
		n = append(n, r.Name)
	}
	return n
}

// CreateAuthCode generates an authorization code record and returns the plain code.
func (s *Service) CreateAuthCode(ctx context.Context, clientID, userID, redirectURI, codeChallenge, codeChallengeMethod string, ttl time.Duration) (string, error) {
	code := uuid.NewString()
	ac := &models.AuthCode{
		ID:                  uuid.NewString(),
		Code:                code,
		ClientID:            clientID,
		UserID:              userID,
		RedirectURI:         redirectURI,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		ExpiresAt:           time.Now().Add(ttl),
		Used:                false,
	}
	if err := s.store.CreateAuthCode(ctx, ac); err != nil {
		return "", err
	}
	return code, nil
}

// ExchangeAuthCode validates an authorization code and returns access, id, refresh tokens.
func (s *Service) ExchangeAuthCode(ctx context.Context, code, clientID, redirectURI, codeVerifier string) (accessToken string, idToken string, refreshToken string, err error) {
	ac, err := s.store.GetAuthCode(ctx, code)
	if err != nil {
		return "", "", "", errors.New("invalid_code")
	}
	if ac.Used || ac.ExpiresAt.Before(time.Now()) {
		return "", "", "", errors.New("invalid_or_expired_code")
	}
	if ac.ClientID != clientID {
		return "", "", "", errors.New("client_mismatch")
	}
	if ac.RedirectURI != redirectURI {
		// allow empty redirect mismatch? enforce exact match
		return "", "", "", errors.New("redirect_uri_mismatch")
	}
	// verify PKCE if code challenge present
	if ac.CodeChallenge != "" {
		if ac.CodeChallengeMethod == "S256" {
			sha := sha256.Sum256([]byte(codeVerifier))
			enc := base64.RawURLEncoding.EncodeToString(sha[:])
			if enc != ac.CodeChallenge {
				return "", "", "", errors.New("invalid_code_verifier")
			}
		} else {
			// plain
			if codeVerifier != ac.CodeChallenge {
				return "", "", "", errors.New("invalid_code_verifier")
			}
		}
	}

	// mark code used
	if err := s.store.MarkAuthCodeUsed(ctx, ac.ID); err != nil {
		return "", "", "", err
	}

	// get user
	u, err := s.store.GetUserByID(ctx, ac.UserID)
	if err != nil {
		return "", "", "", err
	}

	// issue tokens: access + refresh
	access, refresh, err := s.IssueTokens(ctx, u)
	if err != nil {
		return "", "", "", err
	}
	// issue id token
	idt, err := s.IssueIDToken(ctx, u, clientID)
	if err != nil {
		return "", "", "", err
	}
	return access, idt, refresh, nil
}

// IssueIDToken crea un ID Token (JWT) con claims OIDC minimal.
func (s *Service) IssueIDToken(ctx context.Context, u *models.User, audience string) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"iss":   s.cfg.Issuer,
		"sub":   u.ID,
		"aud":   audience,
		"iat":   now.Unix(),
		"exp":   now.Add(s.cfg.JWTExpiry).Unix(),
		"email": u.Email,
	}
	t := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return t.SignedString(s.priv)
}

// JWKS returns a JWKS JSON containing the public key.
func (s *Service) JWKS() (map[string]interface{}, error) {
	// produce JWK for RSA
	n := s.pub.N
	e := s.pub.E
	nBytes := n.Bytes()
	eBytes := big.NewInt(int64(e)).Bytes()
	nEnc := base64.RawURLEncoding.EncodeToString(nBytes)
	eEnc := base64.RawURLEncoding.EncodeToString(eBytes)
	// kid as sha1 of pub DER for brevity
	pubPem, err := s.kp.GetPublicKeyPEM()
	if err != nil {
		return nil, err
	}
	kidBytes := sha1.Sum(pubPem)
	kid := base64.RawURLEncoding.EncodeToString(kidBytes[:])
	jwk := map[string]interface{}{
		"kty": "RSA",
		"use": "sig",
		"alg": "RS256",
		"kid": kid,
		"n":   nEnc,
		"e":   eEnc,
	}
	return map[string]interface{}{"keys": []interface{}{jwk}}, nil
}

// GetOAuthClient fetches an OAuth client by client_id from the store.
func (s *Service) GetOAuthClientByClientID(ctx context.Context, clientID string) (*models.OAuthClient, error) {
	return s.store.GetOAuthClientByClientID(ctx, clientID)
}

// CreateOAuthClient creates a client with hashed secret.
func (s *Service) CreateOAuthClient(ctx context.Context, clientID, rawSecret, redirectURIsCSV, grantTypesCSV string) (*models.OAuthClient, error) {
	// hash secret
	h := sha256.Sum256([]byte(rawSecret))
	secretHash := hex.EncodeToString(h[:])
	c := &models.OAuthClient{
		ID:           uuid.NewString(),
		ClientID:     clientID,
		ClientSecret: secretHash,
		RedirectURIs: redirectURIsCSV,
		GrantTypes:   grantTypesCSV,
	}
	if err := s.store.CreateOAuthClient(ctx, c); err != nil {
		return nil, err
	}
	return c, nil
}

// ValidateClientSecret checks raw secret against stored hash. If stored secret is empty, treat as public client.
func (s *Service) ValidateClientSecret(ctx context.Context, clientID, rawSecret string) (bool, error) {
	c, err := s.store.GetOAuthClientByClientID(ctx, clientID)
	if err != nil {
		return false, err
	}
	if c.ClientSecret == "" {
		// public client
		return true, nil
	}
	h := sha256.Sum256([]byte(rawSecret))
	return hex.EncodeToString(h[:]) == c.ClientSecret, nil
}
