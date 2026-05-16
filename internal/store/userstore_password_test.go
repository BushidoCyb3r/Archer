package store

import (
	"testing"

	"github.com/BushidoCyb3r/Archer/internal/model"
)

// TestSetPassword_RotatesCredential asserts the end-to-end invariant
// SetPassword exists to enforce: after it runs, the OLD password
// stops authenticating and the NEW one starts. Asserting only "the
// password_hash column changed" would still pass if the stored value
// didn't correspond to the requested password — so the test drives
// the full Authenticate path on both sides of the rotation.
func TestSetPassword_RotatesCredential(t *testing.T) {
	us := newAuthTestStore(t)
	u, err := us.CreateUser("rotate@example.com", "Ro", "Tate", "old-password-123", model.RoleAnalyst, model.StatusActive)
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}

	if _, ok := us.Authenticate("rotate@example.com", "old-password-123"); !ok {
		t.Fatal("precondition: original password should authenticate")
	}

	if err := us.SetPassword(u.ID, "fresh-password-456"); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}

	if _, ok := us.Authenticate("rotate@example.com", "old-password-123"); ok {
		t.Error("old password still authenticates after SetPassword")
	}
	if _, ok := us.Authenticate("rotate@example.com", "fresh-password-456"); !ok {
		t.Error("new password does not authenticate after SetPassword")
	}
}
