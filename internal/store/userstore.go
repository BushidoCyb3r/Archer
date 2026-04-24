package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/BushidoCyb3r/Archer/internal/model"
	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

type userSession struct {
	UserID    int
	ExpiresAt time.Time
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
		log.Fatalf("userstore: cannot create data dir %s: %v", dataDir, err)
	}
	dbPath := filepath.Join(dataDir, "archer.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		log.Fatalf("userstore: cannot open database %s: %v", dbPath, err)
	}
	db.SetMaxOpenConns(1) // SQLite is single-writer

	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id            INTEGER PRIMARY KEY AUTOINCREMENT,
			email         TEXT    UNIQUE NOT NULL,
			first_name    TEXT    NOT NULL DEFAULT '',
			last_name     TEXT    NOT NULL DEFAULT '',
			password_hash TEXT    NOT NULL,
			role          TEXT    NOT NULL DEFAULT 'analyst',
			created_at    TEXT    NOT NULL
		)`); err != nil {
		log.Fatalf("userstore: cannot create users table: %v", err)
	}

	us := &UserStore{
		db:       db,
		sessions: make(map[string]userSession),
	}
	go us.pruneSessionsLoop()
	return us
}

// pruneSessionsLoop removes expired sessions once per hour.
func (us *UserStore) pruneSessionsLoop() {
	for range time.Tick(time.Hour) {
		now := time.Now()
		us.mu.Lock()
		for tok, sess := range us.sessions {
			if now.After(sess.ExpiresAt) {
				delete(us.sessions, tok)
			}
		}
		us.mu.Unlock()
	}
}

// DB exposes the underlying database handle so other stores can share it.
func (us *UserStore) DB() *sql.DB { return us.db }

// CreateUser hashes the password and inserts a new user row.
func (us *UserStore) CreateUser(email, firstName, lastName, password, role string) (model.User, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return model.User{}, err
	}
	now := time.Now().UTC().Format("2006-01-02 15:04:05 UTC")
	res, err := us.db.Exec(
		`INSERT INTO users (email, first_name, last_name, password_hash, role, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		email, firstName, lastName, string(hash), role, now,
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
		Role: role, CreatedAt: now,
	}, nil
}

// GetUserByEmail finds a user by email (stored lowercase, matched exactly).
func (us *UserStore) GetUserByEmail(email string) (model.User, bool) {
	var u model.User
	err := us.db.QueryRow(
		`SELECT id, email, first_name, last_name, password_hash, role, created_at
		 FROM users WHERE email = ? COLLATE NOCASE`, email,
	).Scan(&u.ID, &u.Email, &u.FirstName, &u.LastName, &u.PasswordHash, &u.Role, &u.CreatedAt)
	if err != nil {
		return model.User{}, false
	}
	return u, true
}

// GetUserByID finds a user by primary key.
func (us *UserStore) GetUserByID(id int) (model.User, bool) {
	var u model.User
	err := us.db.QueryRow(
		`SELECT id, email, first_name, last_name, password_hash, role, created_at
		 FROM users WHERE id = ?`, id,
	).Scan(&u.ID, &u.Email, &u.FirstName, &u.LastName, &u.PasswordHash, &u.Role, &u.CreatedAt)
	if err != nil {
		return model.User{}, false
	}
	return u, true
}

// ListUsers returns all users without password hashes.
func (us *UserStore) ListUsers() []model.User {
	rows, err := us.db.Query(
		`SELECT id, email, first_name, last_name, role, created_at FROM users ORDER BY id`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []model.User
	for rows.Next() {
		var u model.User
		if err := rows.Scan(&u.ID, &u.Email, &u.FirstName, &u.LastName, &u.Role, &u.CreatedAt); err == nil {
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
func (us *UserStore) Authenticate(email, password string) (model.User, bool) {
	u, ok := us.GetUserByEmail(email)
	if !ok {
		return model.User{}, false
	}
	if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)) != nil {
		return model.User{}, false
	}
	return u, true
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
