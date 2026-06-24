package llm

import (
	"context"
	"net/http"
	"strings"
	"time"
)

// anthropicProvider calls the Anthropic Messages API (POST /v1/messages).
// Thinking is left off and the system prompt instructs a final-answer-only
// reply, so the briefing stays terse and no reasoning leaks into the note.
type anthropicProvider struct {
	key     string
	model   string
	base    string
	timeout time.Duration
}

func (p *anthropicProvider) Name() string { return "anthropic" }

func (p *anthropicProvider) Summarize(ctx context.Context, system, user string) (string, error) {
	body := map[string]any{
		"model":      p.model,
		"max_tokens": maxOutputTokens,
		"system":     system,
		"messages": []map[string]any{
			{"role": "user", "content": user},
		},
	}
	headers := map[string]string{
		"x-api-key":         p.key,
		"anthropic-version": "2023-06-01",
	}
	var out struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		StopReason string `json:"stop_reason"`
	}
	client := &http.Client{Timeout: p.timeout}
	if err := postJSON(ctx, client, p.base+"/v1/messages", headers, body, &out); err != nil {
		return "", err
	}
	var b strings.Builder
	for _, c := range out.Content {
		if c.Type == "text" {
			b.WriteString(c.Text)
		}
	}
	text := strings.TrimSpace(b.String())
	// A safety-classifier decline returns 200 with stop_reason "refusal" and
	// (pre-output) empty content. Surface it distinctly — on a security tool
	// this is a real, recoverable outcome, not a transport failure.
	if out.StopReason == "refusal" && text == "" {
		return "", ErrRefused
	}
	return text, nil
}
