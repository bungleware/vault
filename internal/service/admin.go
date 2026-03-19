package service

import (
	"context"
	"database/sql"
	"time"

	"bungleware/vault/internal/auth"
	"bungleware/vault/internal/db"
	sqlc "bungleware/vault/internal/db/sqlc"
)

type InviteResult struct {
	ID    int64
	Token string
	Email string
}

type ResetLinkResult struct {
	ID    int64
	Token string
	Email string
}

type AdminService interface {
	ListAllUsers(ctx context.Context) ([]sqlc.User, error)
	GetUserByID(ctx context.Context, userID int64) (sqlc.User, error)
	CreateInvite(ctx context.Context, createdBy int64, email string) (InviteResult, error)
	UpdateUserRole(ctx context.Context, adminID, targetUserID int64, isAdmin bool) (sqlc.User, error)
	RenameUser(ctx context.Context, adminID, targetUserID int64, username string) (sqlc.User, error)
	DeleteUser(ctx context.Context, adminID, targetUserID int64) error
	CreateResetLink(ctx context.Context, adminID, targetUserID int64) (ResetLinkResult, error)
}

type adminService struct {
	db         *db.DB
	authConfig auth.Config
}

func NewAdminService(database *db.DB, authConfig auth.Config) AdminService {
	return &adminService{db: database, authConfig: authConfig}
}

func (s *adminService) ListAllUsers(ctx context.Context) ([]sqlc.User, error) {
	return s.db.Queries.ListAllUsers(ctx)
}

func (s *adminService) GetUserByID(ctx context.Context, userID int64) (sqlc.User, error) {
	return s.db.Queries.GetUserByID(ctx, userID)
}

func (s *adminService) CreateInvite(ctx context.Context, createdBy int64, email string) (InviteResult, error) {
	token, err := auth.GenerateSecureToken(32)
	if err != nil {
		return InviteResult{}, err
	}

	inviteToken, err := s.db.Queries.CreateInviteToken(ctx, sqlc.CreateInviteTokenParams{
		TokenHash: auth.HashToken(token, s.authConfig.TokenPepper),
		TokenType: "invite",
		CreatedBy: createdBy,
		Email:     email,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	})
	if err != nil {
		return InviteResult{}, err
	}

	return InviteResult{ID: inviteToken.ID, Token: token, Email: inviteToken.Email}, nil
}

func (s *adminService) UpdateUserRole(ctx context.Context, adminID, targetUserID int64, isAdmin bool) (sqlc.User, error) {
	admin, err := s.db.Queries.GetUserByID(ctx, adminID)
	if err != nil {
		return sqlc.User{}, ErrNotFound
	}
	if !admin.IsOwner {
		return sqlc.User{}, ErrForbidden
	}

	targetUser, err := s.db.Queries.GetUserByID(ctx, targetUserID)
	if err != nil {
		return sqlc.User{}, ErrNotFound
	}
	if targetUser.IsOwner && !isAdmin {
		return sqlc.User{}, ErrForbidden
	}

	return s.db.Queries.UpdateUserRole(ctx, sqlc.UpdateUserRoleParams{
		IsAdmin: isAdmin,
		ID:      targetUserID,
	})
}

func (s *adminService) RenameUser(ctx context.Context, adminID, targetUserID int64, username string) (sqlc.User, error) {
	if adminID != targetUserID {
		return sqlc.User{}, ErrForbidden
	}

	user, err := s.db.Queries.UpdateUsername(ctx, sqlc.UpdateUsernameParams{
		Username: username,
		ID:       targetUserID,
	})
	if err != nil {
		return sqlc.User{}, ErrConflict
	}
	return user, nil
}

func (s *adminService) DeleteUser(ctx context.Context, adminID, targetUserID int64) error {
	targetUser, err := s.db.Queries.GetUserByID(ctx, targetUserID)
	if err != nil {
		return ErrNotFound
	}
	if targetUser.IsOwner {
		return ErrForbidden
	}

	users, err := s.db.Queries.ListAllUsers(ctx)
	if err != nil {
		return err
	}

	adminCount := 0
	for _, u := range users {
		if u.IsAdmin {
			adminCount++
		}
	}
	if adminCount <= 1 && adminID == targetUserID {
		return ErrForbidden
	}

	return s.db.Queries.DeleteUserByID(ctx, targetUserID)
}

func (s *adminService) CreateResetLink(ctx context.Context, adminID, targetUserID int64) (ResetLinkResult, error) {
	user, err := s.db.Queries.GetUserByID(ctx, targetUserID)
	if err != nil {
		return ResetLinkResult{}, ErrNotFound
	}

	if user.IsOwner {
		admin, err := s.db.Queries.GetUserByID(ctx, adminID)
		if err != nil {
			return ResetLinkResult{}, ErrNotFound
		}
		if !admin.IsOwner && admin.ID != user.ID {
			return ResetLinkResult{}, ErrForbidden
		}
	}

	token, err := auth.GenerateSecureToken(32)
	if err != nil {
		return ResetLinkResult{}, err
	}

	resetToken, err := s.db.Queries.CreateResetToken(ctx, sqlc.CreateResetTokenParams{
		TokenHash: auth.HashToken(token, s.authConfig.TokenPepper),
		TokenType: "reset",
		UserID:    sql.NullInt64{Int64: user.ID, Valid: true},
		CreatedBy: adminID,
		Email:     user.Email,
		ExpiresAt: time.Now().Add(1 * time.Hour),
	})
	if err != nil {
		return ResetLinkResult{}, err
	}

	return ResetLinkResult{ID: resetToken.ID, Token: token, Email: resetToken.Email}, nil
}
