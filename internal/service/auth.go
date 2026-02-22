package service

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"time"

	"bungleware/vault/internal/auth"
	"bungleware/vault/internal/db"
	sqlc "bungleware/vault/internal/db/sqlc"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserExists         = errors.New("username or email already exists")
	ErrInvalidToken       = errors.New("invalid or expired token")
	ErrTokenUsed          = errors.New("token already used")
	ErrTokenExpired       = errors.New("token expired")
	ErrInvalidTokenType   = errors.New("invalid token type")
)

type AuthService interface {
	Register(ctx context.Context, input RegisterInput) (*RegisterResult, error)
	RegisterWithInvite(ctx context.Context, input RegisterWithInviteInput) (*RegisterResult, error)
	Login(ctx context.Context, username, password string) (*User, error)
	Me(ctx context.Context, userID int64) (*User, error)
	VerifyCredentials(ctx context.Context, username, password string) (*User, error)

	// User management
	UpdateUsername(ctx context.Context, userID int64, username string) (*User, error)
	DeleteUser(ctx context.Context, userID int64) error

	// Session management
	CreateSession(ctx context.Context, userID int, username string, meta SessionMeta) (*SessionTokens, error)
	RefreshSession(ctx context.Context, refreshToken string, meta SessionMeta) (*SessionTokens, error)
	RevokeRefreshToken(ctx context.Context, refreshToken string) error
	RevokeRefreshTokensByUser(ctx context.Context, userID int64) error
	InvalidateUserSessions(ctx context.Context, userID int64) error
	CheckUsersExist(ctx context.Context) (bool, error)

	ValidateResetToken(ctx context.Context, token string) (bool, error)
	ValidateInviteToken(ctx context.Context, token string) (bool, error)
	ResetPassword(ctx context.Context, token, newPassword string) error

	GetInviteToken(ctx context.Context, token string) (*InviteToken, error)
}

type authService struct {
	db         *db.DB
	authConfig auth.Config
}

func NewAuthService(database *db.DB, authConfig auth.Config) AuthService {
	return &authService{
		db:         database,
		authConfig: authConfig,
	}
}

type RegisterInput struct {
	Username     string
	Email        string
	Password     string
	InstanceName *string
}

type RegisterWithInviteInput struct {
	Username    string
	Email       string
	Password    string
	InviteToken string
}

type RegisterResult struct {
	User *User
}

type SessionTokens struct {
	AccessToken  string
	RefreshToken string
	CSRFToken    string
	User         *User
}

type SessionMeta struct {
	UserAgent string
	IP        string
}

type User struct {
	ID        int64
	Username  string
	Email     string
	IsAdmin   bool
	IsOwner   bool
	CreatedAt *string
	UpdatedAt *string
}

type InviteToken struct {
	ID        int64
	TokenHash string
	TokenType string
	UserID    sql.NullInt64
	Used      bool
	ExpiresAt time.Time
}

func (s *authService) Register(ctx context.Context, input RegisterInput) (*RegisterResult, error) {
	if input.Username == "" || input.Email == "" || input.Password == "" {
		return nil, errors.New("username, email, and password are required")
	}

	passwordHash, err := auth.HashPassword(input.Password)
	if err != nil {
		return nil, err
	}

	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	qtx := s.db.Queries.WithTx(tx)

	userCount, err := qtx.CountUsers(ctx)
	if err != nil {
		return nil, err
	}
	isFirstUser := userCount == 0

	user, err := qtx.CreateUser(ctx, sqlc.CreateUserParams{
		Username:     input.Username,
		Email:        input.Email,
		PasswordHash: passwordHash,
		IsAdmin:      isFirstUser,
		IsOwner:      isFirstUser,
	})
	if err != nil {
		if isUniqueConstraintError(err) {
			slog.WarnContext(ctx, "Registration failed: user already exists",
				"username", input.Username,
				"email", input.Email,
			)
			return nil, ErrUserExists
		}
		return nil, err
	}

	slog.InfoContext(ctx, "User registered",
		"user_id", user.ID,
		"username", user.Username,
		"is_first_user", isFirstUser,
	)

	err = qtx.CreateUserPreferences(ctx, sqlc.CreateUserPreferencesParams{
		UserID:         user.ID,
		DefaultQuality: "lossy",
	})
	if err != nil {
		return nil, err
	}

	if input.InstanceName != nil && *input.InstanceName != "" {
		_, err = qtx.UpsertInstanceSettings(ctx, *input.InstanceName)
		if err != nil {
			return nil, err
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	return &RegisterResult{
		User: sqlcUserToServiceUser(user),
	}, nil
}

func (s *authService) RegisterWithInvite(ctx context.Context, input RegisterWithInviteInput) (*RegisterResult, error) {
	if input.Username == "" || input.Password == "" || input.InviteToken == "" {
		return nil, errors.New("username, password, and invite_token are required")
	}

	inviteToken, err := s.db.Queries.GetInviteTokenByToken(ctx, auth.HashToken(input.InviteToken, s.authConfig.TokenPepper))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrInvalidToken
	}
	if err != nil {
		return nil, err
	}

	if inviteToken.TokenType != "invite" {
		return nil, ErrInvalidTokenType
	}

	if inviteToken.Used {
		return nil, ErrTokenUsed
	}

	if time.Now().After(inviteToken.ExpiresAt) {
		return nil, ErrTokenExpired
	}

	passwordHash, err := auth.HashPassword(input.Password)
	if err != nil {
		return nil, err
	}

	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	qtx := s.db.Queries.WithTx(tx)

	_, err = qtx.GetUserByUsername(ctx, input.Username)
	if err == nil {
		return nil, ErrUserExists
	}
	if err != sql.ErrNoRows {
		return nil, err
	}

	_, err = qtx.GetUserByEmail(ctx, input.Email)
	if err == nil {
		return nil, errors.New("email is already registered")
	}
	if err != sql.ErrNoRows {
		return nil, err
	}

	user, err := qtx.CreateUser(ctx, sqlc.CreateUserParams{
		Username:     input.Username,
		Email:        input.Email,
		PasswordHash: passwordHash,
		IsAdmin:      false,
		IsOwner:      false,
	})
	if err != nil {
		return nil, err
	}

	err = qtx.CreateUserPreferences(ctx, sqlc.CreateUserPreferencesParams{
		UserID:         user.ID,
		DefaultQuality: "lossy",
	})
	if err != nil {
		return nil, err
	}

	_, err = qtx.MarkTokenAsUsed(ctx, inviteToken.ID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrTokenUsed
	}
	if err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	return &RegisterResult{
		User: sqlcUserToServiceUser(user),
	}, nil
}

func (s *authService) Login(ctx context.Context, username, password string) (*User, error) {
	if username == "" || password == "" {
		return nil, errors.New("username and password are required")
	}

	user, err := s.db.GetUserByUsername(ctx, username)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrInvalidCredentials
	}
	if err != nil {
		return nil, err
	}

	if err := auth.VerifyPassword(password, user.PasswordHash); err != nil {
		slog.WarnContext(ctx, "Login failed: invalid password",
			"username", username,
		)
		return nil, ErrInvalidCredentials
	}

	slog.InfoContext(ctx, "User logged in",
		"user_id", user.ID,
		"username", username,
	)

	return sqlcUserToServiceUser(user), nil
}

func (s *authService) Me(ctx context.Context, userID int64) (*User, error) {
	user, err := s.db.GetUserByID(ctx, userID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, sql.ErrNoRows
	}
	if err != nil {
		return nil, err
	}

	return sqlcUserToServiceUser(user), nil
}

func (s *authService) UpdateUsername(ctx context.Context, userID int64, username string) (*User, error) {
	if username == "" {
		return nil, errors.New("username is required")
	}

	user, err := s.db.GetUserByID(ctx, userID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, sql.ErrNoRows
	}
	if err != nil {
		return nil, err
	}

	updatedUser, err := s.db.UpdateUser(ctx, sqlc.UpdateUserParams{
		Username: username,
		Email:    user.Email,
		ID:       userID,
	})
	if err != nil {
		if isUniqueConstraintError(err) {
			return nil, errors.New("username already exists")
		}
		return nil, err
	}

	return sqlcUserToServiceUser(updatedUser), nil
}

func (s *authService) DeleteUser(ctx context.Context, userID int64) error {
	return s.db.Queries.DeleteUserByID(ctx, userID)
}

func (s *authService) CheckUsersExist(ctx context.Context) (bool, error) {
	count, err := s.db.Queries.CountUsers(ctx)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func (s *authService) ValidateResetToken(ctx context.Context, token string) (bool, error) {
	return s.validateToken(ctx, token, "reset")
}

func (s *authService) ValidateInviteToken(ctx context.Context, token string) (bool, error) {
	return s.validateToken(ctx, token, "invite")
}

func (s *authService) validateToken(ctx context.Context, token, tokenType string) (bool, error) {
	inviteToken, err := s.db.Queries.GetInviteTokenByToken(ctx, auth.HashToken(token, s.authConfig.TokenPepper))
	if errors.Is(err, sql.ErrNoRows) {
		tokenPrefix := token
		if len(token) > 8 {
			tokenPrefix = token[:8]
		}
		slog.WarnContext(ctx, "Token validation failed: not found",
			"token_type", tokenType,
			"token_prefix", tokenPrefix,
		)
		return false, ErrInvalidToken
	}
	if err != nil {
		return false, err
	}

	if inviteToken.TokenType != tokenType {
		slog.WarnContext(ctx, "Token validation failed: wrong type",
			"expected_type", tokenType,
			"actual_type", inviteToken.TokenType,
		)
		return false, ErrInvalidTokenType
	}

	if inviteToken.Used {
		slog.WarnContext(ctx, "Token validation failed: already used",
			"token_type", tokenType,
		)
		return false, ErrTokenUsed
	}

	if time.Now().After(inviteToken.ExpiresAt) {
		slog.WarnContext(ctx, "Token validation failed: expired",
			"token_type", tokenType,
			"expires_at", inviteToken.ExpiresAt,
		)
		return false, ErrTokenExpired
	}

	return true, nil
}

func (s *authService) GetInviteToken(ctx context.Context, token string) (*InviteToken, error) {
	inviteToken, err := s.db.Queries.GetInviteTokenByToken(ctx, auth.HashToken(token, s.authConfig.TokenPepper))
	if err != nil {
		return nil, err
	}

	return &InviteToken{
		ID:        inviteToken.ID,
		TokenHash: inviteToken.TokenHash,
		TokenType: inviteToken.TokenType,
		UserID:    inviteToken.UserID,
		Used:      inviteToken.Used,
		ExpiresAt: inviteToken.ExpiresAt,
	}, nil
}

func (s *authService) CreateSession(ctx context.Context, userID int, username string, meta SessionMeta) (*SessionTokens, error) {
	accessToken, err := auth.GenerateToken(userID, username, s.authConfig)
	if err != nil {
		return nil, err
	}

	refreshToken, err := auth.GenerateSecureToken(32)
	if err != nil {
		return nil, err
	}

	refreshHash := auth.HashToken(refreshToken, s.authConfig.TokenPepper)
	expiresAt := time.Now().Add(s.authConfig.RefreshExpiration)

	_, err = s.db.Queries.CreateRefreshToken(ctx, sqlc.CreateRefreshTokenParams{
		UserID:    int64(userID),
		TokenHash: refreshHash,
		ExpiresAt: expiresAt,
		UserAgent: sql.NullString{String: meta.UserAgent, Valid: meta.UserAgent != ""},
		Ip:        sql.NullString{String: meta.IP, Valid: meta.IP != ""},
	})
	if err != nil {
		return nil, err
	}

	csrfToken, err := auth.GenerateSecureToken(16)
	if err != nil {
		return nil, err
	}

	user, err := s.Me(ctx, int64(userID))
	if err != nil {
		return nil, err
	}

	return &SessionTokens{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		CSRFToken:    csrfToken,
		User:         user,
	}, nil
}

func (s *authService) RefreshSession(ctx context.Context, refreshToken string, meta SessionMeta) (*SessionTokens, error) {
	if refreshToken == "" {
		return nil, ErrInvalidToken
	}

	refreshHash := auth.HashToken(refreshToken, s.authConfig.TokenPepper)
	stored, err := s.db.Queries.GetRefreshTokenByHash(ctx, refreshHash)
	if err != nil {
		return nil, ErrInvalidToken
	}
	if stored.RevokedAt.Valid {
		return nil, ErrInvalidToken
	}
	if time.Now().After(stored.ExpiresAt) {
		return nil, ErrTokenExpired
	}

	_ = s.db.Queries.UpdateRefreshTokenLastUsed(ctx, stored.ID)
	_ = s.db.Queries.RevokeRefreshToken(ctx, stored.ID)

	user, err := s.db.Queries.GetUserByID(ctx, stored.UserID)
	if err != nil {
		return nil, err
	}

	return s.CreateSession(ctx, int(user.ID), user.Username, meta)
}

func (s *authService) RevokeRefreshToken(ctx context.Context, refreshToken string) error {
	if refreshToken == "" {
		return nil
	}
	refreshHash := auth.HashToken(refreshToken, s.authConfig.TokenPepper)
	stored, err := s.db.Queries.GetRefreshTokenByHash(ctx, refreshHash)
	if err != nil {
		return nil
	}
	return s.db.Queries.RevokeRefreshToken(ctx, stored.ID)
}

func (s *authService) RevokeRefreshTokensByUser(ctx context.Context, userID int64) error {
	return s.db.Queries.RevokeRefreshTokensByUser(ctx, userID)
}

func (s *authService) InvalidateUserSessions(ctx context.Context, userID int64) error {
	if err := s.db.Queries.UpdateUserSessionInvalidatedAt(ctx, userID); err != nil {
		return err
	}
	return s.db.Queries.RevokeRefreshTokensByUser(ctx, userID)
}

func (s *authService) ResetPassword(ctx context.Context, token, newPassword string) error {
	if token == "" || newPassword == "" {
		return errors.New("token and password are required")
	}

	inviteToken, err := s.db.Queries.GetInviteTokenByToken(ctx, auth.HashToken(token, s.authConfig.TokenPepper))
	if errors.Is(err, sql.ErrNoRows) {
		return ErrInvalidToken
	}
	if err != nil {
		return err
	}
	if inviteToken.TokenType != "reset" {
		return ErrInvalidTokenType
	}
	if inviteToken.Used {
		return ErrTokenUsed
	}
	if time.Now().After(inviteToken.ExpiresAt) {
		return ErrTokenExpired
	}
	if !inviteToken.UserID.Valid {
		return ErrInvalidToken
	}

	passwordHash, err := auth.HashPassword(newPassword)
	if err != nil {
		return err
	}

	if _, err := s.db.Queries.UpdateUserPassword(ctx, sqlc.UpdateUserPasswordParams{
		PasswordHash: passwordHash,
		ID:           inviteToken.UserID.Int64,
	}); err != nil {
		return err
	}

	if _, err := s.db.Queries.MarkTokenAsUsed(ctx, inviteToken.ID); err != nil {
		return err
	}

	return s.InvalidateUserSessions(ctx, inviteToken.UserID.Int64)
}

func sqlcUserToServiceUser(user sqlc.User) *User {
	result := &User{
		ID:       user.ID,
		Username: user.Username,
		Email:    user.Email,
		IsAdmin:  user.IsAdmin,
		IsOwner:  user.IsOwner,
	}

	if user.CreatedAt.Valid {
		formatted := user.CreatedAt.Time.Format("2006-01-02T15:04:05Z07:00")
		result.CreatedAt = &formatted
	}
	if user.UpdatedAt.Valid {
		formatted := user.UpdatedAt.Time.Format("2006-01-02T15:04:05Z07:00")
		result.UpdatedAt = &formatted
	}

	return result
}

func isUniqueConstraintError(err error) bool {
	return err != nil && (err.Error() == "UNIQUE constraint failed: users.username" ||
		err.Error() == "UNIQUE constraint failed: users.email" ||
		err.Error() == "UNIQUE constraint failed: users.email, users.username")
}
func (s *authService) VerifyCredentials(ctx context.Context, username, password string) (*User, error) {
	return s.Login(ctx, username, password)
}
