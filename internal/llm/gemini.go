package llm

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// geminiProvider calls Google's Generative Language API
// (POST /v1beta/models/{model}:generateContent?key=...). The system prompt is
// passed as systemInstruction so it carries the same framing as the other
// providers.
type geminiProvider struct {
	key     string
	model   string
	base    string
	timeout time.Duration
}

func (p *geminiProvider) Name() string { return "gemini" }

func (p *geminiProvider) Summarize(ctx context.Context, system, user string) (string, error) {
	body := map[string]any{
		"systemInstruction": map[string]any{
			"parts": []map[string]any{{"text": system}},
		},
		"contents": []map[string]any{
			{"role": "user", "parts": []map[string]any{{"text": user}}},
		},
		"generationConfig": map[string]any{
			"maxOutputTokens": maxOutputTokens,
		},
	}
	endpoint := p.base + "/v1beta/models/" + url.PathEscape(p.model) + ":generateContent?key=" + url.QueryEscape(p.key)
	var out struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"content"`
			FinishReason string `json:"finishReason"`
		} `json:"candidates"`
	}
	client := &http.Client{Timeout: p.timeout}
	if err := postJSON(ctx, client, endpoint, nil, body, &out); err != nil {
		return "", err
	}
	if len(out.Candidates) == 0 {
		// No candidate is Gemini's shape for a safety block (the prompt or
		// response tripped a safety filter and was withheld).
		return "", ErrRefused
	}
	var b strings.Builder
	for _, part := range out.Candidates[0].Content.Parts {
		b.WriteString(part.Text)
	}
	text := strings.TrimSpace(b.String())
	if text == "" && out.Candidates[0].FinishReason == "SAFETY" {
		return "", ErrRefused
	}
	return text, nil
}
