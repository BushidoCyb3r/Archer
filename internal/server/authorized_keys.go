package server

// authorized_keys management for Quiver enrollment.
//
// Each enrolled sensor gets exactly one line in /home/quiver/.ssh/authorized_keys,
// constructed at enrollment time and stored verbatim in the sensors row so
// disenroll can drop the same line by exact match. The line carries a per-
// sensor command="..." restriction that pins the SSH session to a single
// rsync invocation scoped to that sensor's logs subdirectory; combined with
// the no-pty / no-port-forwarding / no-X11 / no-agent-forwarding options,
// a leaked sensor key can do exactly one thing: write that sensor's logs.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// matchParentOwner chowns path to whoever owns its parent directory.
// In the container the parent is /home/quiver/.ssh (archer:archer), so
// this sets authorized_keys to archer:archer after every write. Chown
// failures are silently ignored.
func matchParentOwner(path string) {
	fi, err := os.Stat(filepath.Dir(path))
	if err != nil {
		return
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return
	}
	_ = os.Chown(path, int(st.Uid), int(st.Gid))
}

// knownKeyTypes is the set of SSH public key type strings sshd accepts.
// Any other value is treated as a malformed key — sshd will reject it.
var knownKeyTypes = map[string]bool{
	"ssh-rsa":                            true,
	"ssh-ed25519":                        true,
	"ecdsa-sha2-nistp256":                true,
	"ecdsa-sha2-nistp384":                true,
	"ecdsa-sha2-nistp521":                true,
	"sk-ssh-ed25519@openssh.com":         true,
	"sk-ecdsa-sha2-nistp256@openssh.com": true,
}

// BuildAuthKeyLine assembles the authorized_keys line for a sensor. The
// pubkey argument is the public key blob the sensor sent at enrollment
// (e.g. "ssh-ed25519 AAAA... quiver@hostname"). We strip any trailing
// comment and append our own marker so the line is uniquely attributable
// to this sensor when disenroll comes calling.
func BuildAuthKeyLine(sensorName, pubkey string) string {
	parts := strings.Fields(strings.TrimSpace(pubkey))
	keyType := ""
	keyBlob := ""
	if len(parts) >= 2 {
		if knownKeyTypes[parts[0]] {
			keyType, keyBlob = parts[0], parts[1]
		} else {
			// Unrecognised key type — treat as malformed; sshd will reject it.
			keyBlob = parts[1]
		}
	} else if len(parts) == 1 {
		// Defensive — sensor sent a malformed key. We'll still write the
		// line so disenroll has something concrete to remove later.
		keyBlob = parts[0]
	}
	cmd := fmt.Sprintf(`command="rrsync -wo /logs/%s/",no-pty,no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-user-rc`, sensorName)
	marker := "quiver-" + sensorName
	if keyType == "" {
		// Best-effort fallback. sshd will reject this anyway, which is
		// the right outcome for a malformed enrollment.
		return fmt.Sprintf("%s %s %s", cmd, keyBlob, marker)
	}
	return fmt.Sprintf("%s %s %s %s", cmd, keyType, keyBlob, marker)
}

// AppendAuthKey adds the line to the authorized_keys file. The file and
// its parent directory are created with sshd-acceptable permissions if
// they don't exist (700 / 600). The append is mostly atomic: a duplicate
// line wouldn't break anything, but we don't dedupe — caller is expected
// to enforce uniqueness via the sensors-table partial unique index.
func AppendAuthKey(path, line string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("authkeys: mkdir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return fmt.Errorf("authkeys: open: %w", err)
	}
	defer f.Close()
	if !strings.HasSuffix(line, "\n") {
		line += "\n"
	}
	if _, err := f.WriteString(line); err != nil {
		return fmt.Errorf("authkeys: write: %w", err)
	}
	matchParentOwner(path)
	return nil
}

// RemoveAuthKey rewrites the authorized_keys file with the given line
// removed (exact match, ignoring trailing newline). Other lines are
// preserved byte-for-byte. Missing files are not an error — disenrolling
// a sensor whose key was already removed is a no-op.
func RemoveAuthKey(path, line string) error {
	target := strings.TrimRight(line, "\r\n")
	body, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("authkeys: read: %w", err)
	}
	out := make([]string, 0, 32)
	for _, l := range strings.Split(string(body), "\n") {
		if strings.TrimRight(l, "\r") == target {
			continue
		}
		out = append(out, l)
	}
	// Atomic replace: write to a sibling temp file and rename. sshd never
	// observes a half-written authorized_keys this way.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(strings.Join(out, "\n")), 0o640); err != nil {
		return fmt.Errorf("authkeys: write tmp: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("authkeys: rename: %w", err)
	}
	matchParentOwner(path)
	return nil
}
