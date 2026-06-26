package llm

import (
	"context"
	"net/http"
	"strings"
	"time"
)

// openAICompatProvider calls any endpoint speaking the OpenAI
// /chat/completions wire format: OpenAI itself, Ollama, LM Studio, vLLM,
// LocalAI. The only differences across them are the base URL and whether a
// bearer key is sent — captured in the constructed struct, so one
// implementation serves the cloud and the air-gapped local paths alike.
type openAICompatProvider struct {
	name    string // "openai" | "ollama" | "dod" | "custom" — for Name()
	key     string // optional (Ollama needs none)
	model   string
	base    string // includes the /v1 segment; endpoint is base + /chat/completions
	timeout time.Duration
}

func (p *openAICompatProvider) Name() string { return p.name }

func (p *openAICompatProvider) Summarize(ctx context.Context, system, user string) (string, error) {
	body := map[string]any{
		"model": p.model,
		"messages": []map[string]any{
			{"role": "system", "content": system},
			{"role": "user", "content": user},
		},
		"max_tokens": maxOutputTokens,
		"stream":     false,
	}
	headers := map[string]string{}
	if p.key != "" {
		headers["Authorization"] = "Bearer " + p.key
	}
	var out struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
	}
	client := &http.Client{Timeout: p.timeout}
	if err := postJSON(ctx, client, p.base+"/chat/completions", headers, body, &out); err != nil {
		return "", err
	}
	if len(out.Choices) == 0 {
		return "", ErrRefused
	}
	text := strings.TrimSpace(out.Choices[0].Message.Content)
	if text == "" && out.Choices[0].FinishReason == "content_filter" {
		return "", ErrRefused
	}
	return text, nil
}
