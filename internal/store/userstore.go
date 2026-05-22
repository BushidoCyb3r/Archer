package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/BushidoCyb3r/Archer/internal/model"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/text/unicode/norm"
	_ "modernc.org/sqlite"
)

type userSession struct {
	UserID    int
	ExpiresAt time.Time
}

// timingPadHash is a precomputed bcrypt hash used to equalize the latency
// of registration code paths that abort before hashing the real password.
// Without it, an attacker could distinguish "email already registered"
// (fast) from "fresh registration" (~100 ms bcrypt) by timing alone — and
// thereby enumerate valid accounts despite identical response content.
var timingPadHash []byte

func init() {
	timingPadHash, _ = bcrypt.GenerateFromPassword([]byte("archer-timing-pad"), bcrypt.DefaultCost)
}

// EnumerationTimingPad runs a throwaway bcrypt comparison so callers that
// bail out early in registration take roughly the same wall-clock time as
// a real registration. Result is intentionally discarded.
func (us *UserStore) EnumerationTimingPad(password string) {
	_ = bcrypt.CompareHashAndPassword(timingPadHash, []byte(password))
}

// NormalizeEmail trims whitespace, applies Unicode NFC normalization,
// and lowercases. SQLite's COLLATE NOCASE only folds ASCII, and Go's
// strings.ToLower handles Unicode case folding but does NOT normalize
// composed-vs-decomposed forms — so `café@example.com` written as
// NFC (U+00E9) and NFD (U+0065 U+0301) would hash to different keys
// in both the Go-side EmailExists map and the SQLite uniqueness
// check. NFC-then-fold gives a single canonical form for both store
// and lookup paths. Apply at every email-entry boundary (registration,
// admin user-create, login). v0.14.5 NEW-51.
func NormalizeEmail(s string) string {
	return strings.ToLower(norm.NFC.String(strings.TrimSpace(s)))
}

// UserStore persists user accounts in a SQLite database at /data/archer.db.
// Sessions are kept in memory only — they are intentionally ephemeral.
type UserStore struct {
	db       *sql.DB
	mu       sync.RWMutex
	sessions map[string]userSession
}

func NewUserStore(dataDir string) *UserStore {
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		slog.Error("userstore: cannot create data dir", "path", dataDir, "err", err)
		os.Exit(1)
	}
	dbPath := filepath.Join(dataDir, "archer.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		slog.Error("userstore: cannot open database", "path", dbPath, "err", err)
		os.Exit(1)
	}
	db.SetMaxOpenConns(1) // SQLite is single-writer

	// Run schema migrations once at startup. NewUserStore owns the DB
	// connection lifecycle, so this is the natural place to ensure the
	// schema matches what handler code expects before any read or write
	// hits a missing column. Failure is fatal — a half-applied schema
	// would otherwise yield mysterious runtime errors downstream.
	if err := RunMigrations(db); err != nil {
		slog.Error("userstore: schema migrations failed", "err", err)
		os.Exit(1)
	}

	us := &UserStore{
		db:       db,
		sessions: make(map[string]userSession),
	}
	return us
}

// PruneExpiredSessions drops every in-memory session past its expiry.
// One pass — the periodic cadence is owned by the server's shared
// startPruneLoop ("sessions", hourly) rather than a goroutine wired
// from this constructor, so every TTL sweep starts from one place
// (NEW-95 / TODO §1b). Idempotent and lock-guarded; safe to call at
// boot (which the shared loop now does — a long-stopped instance
// sheds stale sessions immediately instead of waiting the first hour).
func (us *UserStore) PruneExpiredSessions() {
	now := time.Now()
	us.mu.Lock()
	defer us.mu.Unlock()
	for tok, sess := range us.sessions {
		if now.After(sess.ExpiresAt) {
			delete(us.sessions, tok)
		}
	}
}

// DB exposes the underlying database handle so other stores can share it.
func (us *UserStore) DB() *sql.DB { return us.db }

// CreateUser hashes the password and inserts a new user row.
func (us *UserStore) CreateUser(email, firstName, lastName, password, role, status string) (model.User, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return model.User{}, err
	}
	now := time.Now().UTC().Format("2006-01-02 15:04:05 UTC")
	res, err := us.db.Exec(
		`INSERT INTO users (email, first_name, last_name, password_hash, role, status, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		email, firstName, lastName, string(hash), role, status, now,
	)
	if err != nil {
		return model.User{}, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return model.User{}, err
	}
	return model.User{
		ID: int(id), Email: email,
		FirstName: firstName, LastName: lastName,
		Role: role, Status: status, CreatedAt: now,
	}, nil
}

// GetUserByEmail finds a user by email (stored lowercase, matched exactly).
func (us *UserStore) GetUserByEmail(email string) (model.User, bool) {
	var u model.User
	err := us.db.QueryRow(
		`SELECT id, email, first_name, last_name, password_hash, role, status, created_at
		 FROM users WHERE email = ? COLLATE NOCASE`, email,
	).Scan(&u.ID, &u.Email, &u.FirstName, &u.LastName, &u.PasswordHash, &u.Role, &u.Status, &u.CreatedAt)
	if err != nil {
		return model.User{}, false
	}
	return u, true
}

// GetUserByID finds a user by primary key.
func (us *UserStore) GetUserByID(id int) (model.User, bool) {
	var u model.User
	err := us.db.QueryRow(
		`SELECT id, email, first_name, last_name, password_hash, role, status, created_at
		 FROM users WHERE id = ?`, id,
	).Scan(&u.ID, &u.Email, &u.FirstName, &u.LastName, &u.PasswordHash, &u.Role, &u.Status, &u.CreatedAt)
	if err != nil {
		return model.User{}, false
	}
	return u, true
}

// ListUsers returns all users without password hashes.
func (us *UserStore) ListUsers() []model.User {
	rows, err := us.db.Query(
		`SELECT id, email, first_name, last_name, role, status, created_at FROM users ORDER BY id`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []model.User
	for rows.Next() {
		var u model.User
		if err := rows.Scan(&u.ID, &u.Email, &u.FirstName, &u.LastName, &u.Role, &u.Status, &u.CreatedAt); err == nil {
			out = append(out, u)
		}
	}
	return out
}

// UserCount returns the number of registered users.
func (us *UserStore) UserCount() int {
	var n int
	us.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n)
	return n
}

// EmailExists reports whether an email is already registered.
func (us *UserStore) EmailExists(email string) bool {
	var n int
	us.db.QueryRow(`SELECT COUNT(*) FROM users WHERE email = ? COLLATE NOCASE`, email).Scan(&n)
	return n > 0
}

// Authenticate checks credentials and returns the user on success.
//
// Both failure paths (unknown email, wrong password) run a bcrypt
// comparison so wall-clock latency is roughly equal across the two
// outcomes. Pre-v0.14.4 the unknown-email path returned early
// without invoking bcrypt while the wrong-password path ran the
// full bcrypt cost (~200ms at DefaultCost) — an attacker measuring
// response time could enumerate registered emails by their latency
// difference. NEW-39's rate limit slows enumeration but the leak
// was still present within each per-IP window (10 attempts/min ×
// over hours = a real signal). Same timing-pad pattern the
// registration path already uses for the same reason. v0.14.4
// NEW-46.
func (us *UserStore) Authenticate(email, password string) (model.User, bool) {
	u, ok := us.GetUserByEmail(email)
	if !ok {
		us.EnumerationTimingPad(password)
		return model.User{}, false
	}
	if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)) != nil {
		return model.User{}, false
	}
	return u, true
}

// SetPassword bcrypt-hashes newPassword and replaces the stored hash
// for the given user. Callers (self-service change, admin reset) have
// already resolved the user, so a missing row can't happen here — the
// only error surfaces are bcrypt and the SQL write.
func (us *UserStore) SetPassword(id int, newPassword string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	_, err = us.db.Exec(`UPDATE users SET password_hash = ? WHERE id = ?`, string(hash), id)
	return err
}

// UpdateUserRole changes a user's role.
func (us *UserStore) UpdateUserRole(id int, role string) bool {
	res, err := us.db.Exec(`UPDATE users SET role = ? WHERE id = ?`, role, id)
	if err != nil {
		return false
	}
	n, _ := res.RowsAffected()
	return n > 0
}

// ApproveUser flips a pending account to active.
func (us *UserStore) ApproveUser(id int) bool {
	res, err := us.db.Exec(`UPDATE users SET status = 'active' WHERE id = ?`, id)
	if err != nil {
		return false
	}
	n, _ := res.RowsAffected()
	return n > 0
}

// DeleteUser removes a user by ID.
func (us *UserStore) DeleteUser(id int) bool {
	res, err := us.db.Exec(`DELETE FROM users WHERE id = ?`, id)
	if err != nil {
		return false
	}
	n, _ := res.RowsAffected()
	return n > 0
}

// ── Sessions (in-memory, intentionally ephemeral) ─────────────────────────

// CreateSession generates a secure token valid for 24 hours.
func (us *UserStore) CreateSession(userID int) string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	token := hex.EncodeToString(b)
	us.mu.Lock()
	us.sessions[token] = userSession{UserID: userID, ExpiresAt: time.Now().Add(24 * time.Hour)}
	us.mu.Unlock()
	return token
}

// GetSession resolves a token to a user. Returns false if missing or expired.
func (us *UserStore) GetSession(token string) (model.User, bool) {
	us.mu.RLock()
	sess, ok := us.sessions[token]
	us.mu.RUnlock()
	if !ok || time.Now().After(sess.ExpiresAt) {
		if ok {
			us.mu.Lock()
			delete(us.sessions, token)
			us.mu.Unlock()
		}
		return model.User{}, false
	}
	return us.GetUserByID(sess.UserID)
}

// DeleteSession removes a session (logout).
func (us *UserStore) DeleteSession(token string) {
	us.mu.Lock()
	delete(us.sessions, token)
	us.mu.Unlock()
}

// DeleteSessionsForUser drops every active session owned by the
// given user. Called from admin-side mutation paths (role change,
// approve, delete) so a privilege transition doesn't leave a
// long-lived 24-hour session continuing to act under the old
// identity. Audit 2026-05-10 NEW-8.
func (us *UserStore) DeleteSessionsForUser(userID int) {
	us.mu.Lock()
	for token, sess := range us.sessions {
		if sess.UserID == userID {
			delete(us.sessions, token)
		}
	}
	us.mu.Unlock()
}
