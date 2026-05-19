package store

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"time"
)

// ServiceToken is the public projection of a service_tokens row.
// The raw token is never stored and never appears in this struct —
// it is returned once by CreateServiceToken and must be captured by
// the caller.
type ServiceToken struct {
	ID        int64  `json:"id"`
	Label     string `json:"label"`
	CreatedAt int64  `json:"created_at"`
	CreatedBy string `json:"created_by"`
}

// CreateServiceToken generates a new service token, stores its SHA-256
// hash, and returns the raw token. The token is a 32-byte random value
// Base64URL-encoded and prefixed "archer_" so it's identifiable if
// accidentally committed to config or source. The raw value is shown
// to the admin exactly once; it is unrecoverable after this call.
func (s *Store) CreateServiceToken(label, createdBy string) (int64, string, error) {
	if s.db == nil {
		return 0, "", fmt.Errorf("store not initialised")
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return 0, "", fmt.Errorf("generate service token: %w", err)
	}
	token := "archer_" + base64.RawURLEncoding.EncodeToString(raw)
	h := sha256.Sum256([]byte(token))
	hash := hex.EncodeToString(h[:])

	res, err := s.db.Exec(
		`INSERT INTO service_tokens(label, token_hash, created_at, created_by) VALUES(?,?,?,?)`,
		label, hash, time.Now().Unix(), createdBy,
	)
	if err != nil {
		return 0, "", fmt.Errorf("insert service token: %w", err)
	}
	id, _ := res.LastInsertId()
	return id, token, nil
}

// GetServiceToken returns the metadata for a single token by id.
func (s *Store) GetServiceToken(id int64) (ServiceToken, bool) {
	if s.db == nil {
		return ServiceToken{}, false
	}
	var t ServiceToken
	err := s.db.QueryRow(
		`SELECT id, label, created_at, created_by FROM service_tokens WHERE id=?`, id,
	).Scan(&t.ID, &t.Label, &t.CreatedAt, &t.CreatedBy)
	if err != nil {
		return ServiceToken{}, false
	}
	return t, true
}

// ListServiceTokens returns all tokens sorted by id. Hashes are never
// included in the result.
func (s *Store) ListServiceTokens() []ServiceToken {
	out := []ServiceToken{}
	if s.db == nil {
		return out
	}
	rows, err := s.db.Query(
		`SELECT id, label, created_at, created_by FROM service_tokens ORDER BY id`,
	)
	if err != nil {
		log.Printf("store: list service tokens: %v", err)
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var t ServiceToken
		if err := rows.Scan(&t.ID, &t.Label, &t.CreatedAt, &t.CreatedBy); err != nil {
			log.Printf("store: scan service token: %v", err)
			continue
		}
		out = append(out, t)
	}
	return out
}

// RevokeServiceToken deletes the token with the given id.
// Returns true if a row was deleted, false if the id was not found.
func (s *Store) RevokeServiceToken(id int64) bool {
	if s.db == nil {
		return false
	}
	res, err := s.db.Exec(`DELETE FROM service_tokens WHERE id=?`, id)
	if err != nil {
		log.Printf("store: revoke service token: %v", err)
		return false
	}
	n, _ := res.RowsAffected()
	return n > 0
}

// ValidateServiceToken reports whether the raw token matches any stored
// hash. The raw value is hashed before the DB lookup; no raw credential
// is ever queried.
func (s *Store) ValidateServiceToken(raw string) bool {
	if s.db == nil || raw == "" {
		return false
	}
	h := sha256.Sum256([]byte(raw))
	hash := hex.EncodeToString(h[:])
	var count int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM service_tokens WHERE token_hash=?`, hash).Scan(&count)
	return count > 0
}
