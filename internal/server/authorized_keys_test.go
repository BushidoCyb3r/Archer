package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildAuthKeyLine_HasAllParts(t *testing.T) {
	line := BuildAuthKeyLine("zeek-01", "ssh-ed25519 AAAAC3blob quiver@host")
	if !strings.Contains(line, `command="rrsync -wo /logs/zeek-01/"`) {
		t.Errorf("rrsync command missing or wrong path: %s", line)
	}
	for _, opt := range []string{"no-pty", "no-port-forwarding", "no-X11-forwarding", "no-agent-forwarding", "no-user-rc"} {
		if !strings.Contains(line, opt) {
			t.Errorf("missing safety option %s: %s", opt, line)
		}
	}
	if !strings.Contains(line, "ssh-ed25519 AAAAC3blob") {
		t.Errorf("key type/blob missing: %s", line)
	}
	if !strings.HasSuffix(line, "quiver-zeek-01") {
		t.Errorf("missing per-sensor marker suffix: %s", line)
	}
}

func TestBuildAuthKeyLine_HandlesMissingComment(t *testing.T) {
	// Pubkey with no trailing comment — sensor's fresh ssh-keygen output
	// can look like this if -C was never set.
	line := BuildAuthKeyLine("alpha", "ssh-ed25519 AAAAblob")
	if !strings.HasSuffix(line, "quiver-alpha") {
		t.Errorf("marker should still be appended: %s", line)
	}
}

func TestBuildAuthKeyLine_RejectsUnknownKeyType(t *testing.T) {
	// An unrecognised key type should not appear in the authorized_keys line.
	// sshd will reject the line regardless; the goal is to keep
	// attacker-chosen type strings out of the file.
	line := BuildAuthKeyLine("sensor1", "unknown-type AAAAC3blob quiver@host")
	if strings.Contains(line, "unknown-type") {
		t.Errorf("unknown key type should not appear in authorized_keys line: %s", line)
	}
	// The blob and sensor marker must still be present so disenroll can clean up.
	if !strings.Contains(line, "AAAAC3blob") {
		t.Errorf("key blob should still be written for cleanup: %s", line)
	}
	if !strings.HasSuffix(line, "quiver-sensor1") {
		t.Errorf("sensor marker should still be present: %s", line)
	}
}

func TestAppendRemoveAuthKey_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "authorized_keys")

	lineA := BuildAuthKeyLine("alpha", "ssh-ed25519 AAAAA quiver@a")
	lineB := BuildAuthKeyLine("bravo", "ssh-ed25519 BBBBB quiver@b")

	if err := AppendAuthKey(path, lineA); err != nil {
		t.Fatalf("append A: %v", err)
	}
	if err := AppendAuthKey(path, lineB); err != nil {
		t.Fatalf("append B: %v", err)
	}

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), lineA) {
		t.Errorf("lineA missing after append:\n%s", body)
	}
	if !strings.Contains(string(body), lineB) {
		t.Errorf("lineB missing after append:\n%s", body)
	}

	if err := RemoveAuthKey(path, lineA); err != nil {
		t.Fatalf("remove A: %v", err)
	}
	body, _ = os.ReadFile(path)
	if strings.Contains(string(body), `quiver-alpha`) {
		t.Errorf("lineA marker should be gone:\n%s", body)
	}
	if !strings.Contains(string(body), `quiver-bravo`) {
		t.Errorf("lineB should still be present:\n%s", body)
	}

	// Permissions should survive the rewrite.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Errorf("authorized_keys mode drifted: got %o, want 640", info.Mode().Perm())
	}

	// Removing the same line again should be a clean no-op.
	if err := RemoveAuthKey(path, lineA); err != nil {
		t.Errorf("idempotent remove should not error: %v", err)
	}

	// Removing the last live line leaves an empty file (one trailing newline).
	if err := RemoveAuthKey(path, lineB); err != nil {
		t.Fatalf("remove B: %v", err)
	}
	body, _ = os.ReadFile(path)
	if cleaned := strings.TrimSpace(string(body)); cleaned != "" {
		t.Errorf("file should be empty after removing all keys, got: %q", cleaned)
	}
}

func TestRemoveAuthKey_MissingFile(t *testing.T) {
	// Disenrolling a sensor whose key file was already nuked manually
	// should not error.
	if err := RemoveAuthKey(filepath.Join(t.TempDir(), "nope"), "any line"); err != nil {
		t.Errorf("remove from missing file should be no-op, got: %v", err)
	}
}

func TestAppendAuthKey_PreservesOtherLines(t *testing.T) {
	// An admin who manually edited authorized_keys (e.g. to add a personal
	// debug key) should not lose those edits when Quiver appends or
	// removes its own per-sensor lines.
	dir := t.TempDir()
	path := filepath.Join(dir, "authorized_keys")
	manual := "# admin-managed line\nssh-ed25519 ZZZZmanual operator@laptop\n"
	if err := os.WriteFile(path, []byte(manual), 0o600); err != nil {
		t.Fatal(err)
	}
	q := BuildAuthKeyLine("charlie", "ssh-ed25519 CCCCC quiver@c")
	if err := AppendAuthKey(path, q); err != nil {
		t.Fatal(err)
	}
	if err := RemoveAuthKey(path, q); err != nil {
		t.Fatal(err)
	}
	body, _ := os.ReadFile(path)
	if !strings.Contains(string(body), "# admin-managed line") {
		t.Errorf("manual comment line was lost:\n%s", body)
	}
	if !strings.Contains(string(body), "ZZZZmanual") {
		t.Errorf("manual key line was lost:\n%s", body)
	}
}
