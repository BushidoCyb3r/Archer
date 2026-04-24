package model

// Role constants for user access control.
const (
	RoleAdmin   = "admin"
	RoleAnalyst = "analyst"
	RoleViewer  = "viewer"
)

// ValidRoles is the canonical set of allowed roles.
var ValidRoles = []string{RoleAdmin, RoleAnalyst, RoleViewer}

// IsValidRole reports whether r is a recognised role.
func IsValidRole(r string) bool {
	for _, v := range ValidRoles {
		if v == r {
			return true
		}
	}
	return false
}

// User represents an authenticated Archer analyst.
type User struct {
	ID           int    `json:"id"`
	Email        string `json:"email"`
	FirstName    string `json:"first_name"`
	LastName     string `json:"last_name"`
	PasswordHash string `json:"password_hash"`
	Role         string `json:"role"` // "admin" | "analyst"
	CreatedAt    string `json:"created_at"`
}

// DisplayName returns "FirstName LastName" or falls back to email.
func (u User) DisplayName() string {
	if u.FirstName != "" || u.LastName != "" {
		return u.FirstName + " " + u.LastName
	}
	return u.Email
}

// Note is an analyst annotation attached to a finding.
type Note struct {
	Text        string `json:"text"`
	Author      string `json:"author"`       // display name
	AuthorEmail string `json:"author_email"`
	Timestamp   string `json:"timestamp"`
}
