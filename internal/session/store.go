package session

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/freekieb7/go-lock/internal/database"
	"github.com/freekieb7/go-lock/internal/util"
	"github.com/google/uuid"
)

const (
	CookieName string = "SID"

	SessionExpiryDefaultSeconds uint = 3600 * 8       // 8 hours
	SessionExpiryRememberMe     uint = 3600 * 24 * 30 // 30 days
)

var (
	ErrSessionNotFound        = fmt.Errorf("session not found")
	ContextKey         string = "session"
)

type Store struct {
	DB *database.Database
}

func NewStore(db *database.Database) Store {
	return Store{
		DB: db,
	}
}

func (s *Store) NewSession() (Session, error) {
	token, err := util.GenerateRandomString(32)
	if err != nil {
		return Session{}, fmt.Errorf("failed to generate session token: %w", err)
	}

	return Session{
		Token:     token,
		Data:      map[string]any{},
		ExpiresAt: time.Now().Add(time.Duration(SessionExpiryDefaultSeconds) * time.Second),
	}, nil
}

func (s *Store) GetSessionByToken(ctx context.Context, token string) (Session, error) {
	var sess Session
	var userID *uuid.UUID
	var dataBytes json.RawMessage

	query := `SELECT id, user_id, data, expires_at, created_at FROM tbl_session WHERE token = $1 AND expires_at > NOW()`
	row := s.DB.QueryRow(ctx, query, token)
	if err := row.Scan(&sess.ID, &userID, &dataBytes, &sess.ExpiresAt, &sess.CreatedAt); err != nil {
		if err == database.ErrNoRows {
			return Session{}, ErrSessionNotFound
		}
		return Session{}, fmt.Errorf("failed to get session by token: %w", err)
	}

	if err := json.Unmarshal(dataBytes, &sess.Data); err != nil {
		return Session{}, fmt.Errorf("failed to unmarshal session data: %w", err)
	}

	sess.Token = token

	if userID != nil {
		sess.UserID = *userID
	}

	if sess.Data == nil {
		sess.Data = make(map[string]any)
	}

	return sess, nil
}

func (s *Store) SaveSession(ctx context.Context, sess Session) (Session, error) {
	data, err := json.Marshal(sess.Data)
	if err != nil {
		return Session{}, fmt.Errorf("failed to marshal session data: %w", err)
	}

	var userID *uuid.UUID
	if sess.UserID == uuid.Nil {
		userID = nil
	} else {
		userID = &sess.UserID
	}

	if sess.ID == uuid.Nil {
		if err := s.DB.QueryRow(ctx, `INSERT INTO tbl_session (token, user_id, data, expires_at) VALUES ($1, $2, $3, $4) RETURNING id, created_at`, sess.Token, userID, data, sess.ExpiresAt).Scan(&sess.ID, &sess.CreatedAt); err != nil {
			return Session{}, fmt.Errorf("failed to create session: %w", err)
		}
		return sess, nil
	}

	if _, err := s.DB.Exec(ctx, `UPDATE tbl_session SET user_id = $1, data = $2, expires_at = $3 WHERE id = $4`, userID, data, sess.ExpiresAt, sess.ID); err != nil {
		return Session{}, fmt.Errorf("failed to update session: %w", err)
	}
	return sess, nil
}

func (s *Store) RegenerateSession(ctx context.Context, sess Session) (Session, error) {
	if sess.ID == uuid.Nil {
		return Session{}, fmt.Errorf("cannot regenerate token for new session")
	}

	oldToken := sess.Token
	newToken, err := util.GenerateRandomString(32)
	if err != nil {
		return Session{}, fmt.Errorf("failed to generate new session token: %w", err)
	}

	if _, err := s.DB.Exec(ctx, `UPDATE tbl_session SET token = $1 WHERE token = $2`, newToken, oldToken); err != nil {
		return Session{}, fmt.Errorf("failed to regenerate session token: %w", err)
	}

	sess.Token = newToken
	return sess, nil
}

func (s *Store) DeleteSession(ctx context.Context, token string) error {
	if _, err := s.DB.Exec(ctx, `DELETE FROM tbl_session WHERE token = $1`, token); err != nil {
		return fmt.Errorf("failed to delete session: %w", err)
	}
	return nil
}
