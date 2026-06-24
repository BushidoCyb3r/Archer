package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// postJSON sends body as JSON to url with the given headers and decodes the
// response into out. It bounds the response read and treats any non-2xx
// status as an error carrying a snippet of the body for diagnostics.
func postJSON(ctx context.Context, client *http.Client, url string, headers map[string]string, body, out any) error {
	buf, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(buf))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	limited := io.LimitReader(resp.Body, maxResponseBytes)
	raw, _ := io.ReadAll(limited)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("provider returned %d: %s", resp.StatusCode, snippet(raw))
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

// snippet trims a response body to a short, single-line form for error
// messages — enough to diagnose a misconfiguration without dumping a page.
func snippet(b []byte) string {
	const max = 300
	s := string(b)
	if len(s) > max {
		s = s[:max] + "…"
	}
	return s
}
