package llm

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// captureServer records the last request body + headers and replies with a
// fixed JSON payload, so each provider test can assert both the wire shape it
// sends and that it parses the reply correctly.
func captureServer(t *testing.T, reply string) (*httptest.Server, *map[string]any, *http.Header) {
	t.Helper()
	var body map[string]any
	var hdr http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		hdr = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, reply)
	}))
	t.Cleanup(srv.Close)
	return srv, &body, &hdr
}

func TestAnthropicWireContract(t *testing.T) {
	srv, body, hdr := captureServer(t, `{"content":[{"type":"text","text":"the briefing"}],"stop_reason":"end_turn"}`)
	p, err := NewProvider(Settings{Provider: "anthropic", APIKey: "k", BaseURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	out, err := p.Summarize(context.Background(), "sys", "usr")
	if err != nil {
		t.Fatal(err)
	}
	if out != "the briefing" {
		t.Errorf("parsed text = %q", out)
	}
	if hdr.Get("x-api-key") != "k" || hdr.Get("anthropic-version") != "2023-06-01" {
		t.Errorf("missing anthropic headers: %v", *hdr)
	}
	if (*body)["model"] != "claude-opus-4-8" {
		t.Errorf("default model not applied: %v", (*body)["model"])
	}
	if (*body)["system"] != "sys" {
		t.Errorf("system not sent: %v", (*body)["system"])
	}
}

func TestAnthropicRefusal(t *testing.T) {
	srv, _, _ := captureServer(t, `{"content":[],"stop_reason":"refusal"}`)
	p, _ := NewProvider(Settings{Provider: "anthropic", APIKey: "k", BaseURL: srv.URL})
	if _, err := p.Summarize(context.Background(), "s", "u"); err != ErrRefused {
		t.Errorf("expected ErrRefused, got %v", err)
	}
}

func TestGeminiWireContract(t *testing.T) {
	srv, body, _ := captureServer(t, `{"candidates":[{"content":{"parts":[{"text":"g out"}]},"finishReason":"STOP"}]}`)
	p, err := NewProvider(Settings{Provider: "gemini", APIKey: "k", Model: "gemini-x", BaseURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	out, err := p.Summarize(context.Background(), "sys", "usr")
	if err != nil {
		t.Fatal(err)
	}
	if out != "g out" {
		t.Errorf("parsed text = %q", out)
	}
	si, _ := (*body)["systemInstruction"].(map[string]any)
	if si == nil {
		t.Errorf("systemInstruction not sent: %v", *body)
	}
}

func TestGeminiSafetyBlock(t *testing.T) {
	srv, _, _ := captureServer(t, `{"candidates":[]}`)
	p, _ := NewProvider(Settings{Provider: "gemini", APIKey: "k", Model: "m", BaseURL: srv.URL})
	if _, err := p.Summarize(context.Background(), "s", "u"); err != ErrRefused {
		t.Errorf("expected ErrRefused, got %v", err)
	}
}

func TestOpenAICompatWireContract(t *testing.T) {
	srv, body, hdr := captureServer(t, `{"choices":[{"message":{"content":"oai out"},"finish_reason":"stop"}]}`)
	p, err := NewProvider(Settings{Provider: "openai", APIKey: "sk-x", Model: "gpt-x", BaseURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	out, err := p.Summarize(context.Background(), "sys", "usr")
	if err != nil {
		t.Fatal(err)
	}
	if out != "oai out" {
		t.Errorf("parsed text = %q", out)
	}
	if hdr.Get("Authorization") != "Bearer sk-x" {
		t.Errorf("bearer auth not sent: %v", *hdr)
	}
	msgs, _ := (*body)["messages"].([]any)
	if len(msgs) != 2 {
		t.Errorf("expected system+user messages, got %v", (*body)["messages"])
	}
}

// Ollama is the same wire format with no key — assert no Authorization header
// is sent (the air-gapped local path).
func TestOllamaSendsNoAuthHeader(t *testing.T) {
	srv, _, hdr := captureServer(t, `{"choices":[{"message":{"content":"local out"}}]}`)
	p, err := NewProvider(Settings{Provider: "ollama", Model: "llama3.1", BaseURL: srv.URL + "/v1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Summarize(context.Background(), "s", "u"); err != nil {
		t.Fatal(err)
	}
	if hdr.Get("Authorization") != "" {
		t.Errorf("ollama must not send an Authorization header, got %q", hdr.Get("Authorization"))
	}
}

// The DoD GenAI platform rides the OpenAI-compatible path with a bearer token
// and an operator-supplied enclave base URL.
func TestDoDGenAIWireContract(t *testing.T) {
	srv, body, hdr := captureServer(t, `{"choices":[{"message":{"content":"dod out"}}]}`)
	p, err := NewProvider(Settings{Provider: "dod", APIKey: "tok", Model: "gpt-x", BaseURL: srv.URL + "/v1"})
	if err != nil {
		t.Fatal(err)
	}
	if p.Name() != "dod" {
		t.Errorf("name = %q, want dod", p.Name())
	}
	out, err := p.Summarize(context.Background(), "sys", "usr")
	if err != nil {
		t.Fatal(err)
	}
	if out != "dod out" {
		t.Errorf("parsed text = %q", out)
	}
	if hdr.Get("Authorization") != "Bearer tok" {
		t.Errorf("dod bearer auth not sent: %v", *hdr)
	}
	if (*body)["model"] != "gpt-x" {
		t.Errorf("model not sent: %v", (*body)["model"])
	}
}

// The system prompt must keep its injection guard: evidence carries strings
// observed on the wire, so the model must be told to treat all of it as data.
func TestSystemPromptHasInjectionGuard(t *testing.T) {
	low := strings.ToLower(SystemPrompt)
	if !strings.Contains(low, "untrusted") || !strings.Contains(low, "never as instructions") {
		t.Error("system prompt lost its prompt-injection guard")
	}
}

func TestNewProviderValidation(t *testing.T) {
	cases := []struct {
		name string
		s    Settings
	}{
		{"unknown provider", Settings{Provider: "bedrock"}},
		{"anthropic no key", Settings{Provider: "anthropic"}},
		{"gemini no model", Settings{Provider: "gemini", APIKey: "k"}},
		{"openai no key", Settings{Provider: "openai", Model: "m"}},
		{"ollama no base", Settings{Provider: "ollama", Model: "m"}},
		{"ollama no model", Settings{Provider: "ollama", BaseURL: "http://x:11434/v1"}},
		{"anthropic cleartext base", Settings{Provider: "anthropic", APIKey: "k", BaseURL: "http://proxy.example.com"}},
		{"openai cleartext base", Settings{Provider: "openai", APIKey: "k", Model: "m", BaseURL: "http://gw.example.com/v1"}},
		{"gemini cleartext base", Settings{Provider: "gemini", APIKey: "k", Model: "m", BaseURL: "http://gw.example.com"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := NewProvider(c.s); err == nil {
				t.Errorf("expected validation error for %s", c.name)
			}
		})
	}
}

// A cloud provider accepts https and loopback-http base URLs (the latter is a
// local TLS-terminating proxy), but rejects cleartext to a remote host — that
// rejection is covered in TestNewProviderValidation.
func TestCloudProviderAcceptsHTTPSAndLoopback(t *testing.T) {
	ok := []Settings{
		{Provider: "anthropic", APIKey: "k", BaseURL: "https://api.anthropic.com"},
		{Provider: "openai", APIKey: "k", Model: "m", BaseURL: "https://gw.example.com/v1"},
		{Provider: "anthropic", APIKey: "k", BaseURL: "http://localhost:8080"},
		{Provider: "openai", APIKey: "k", Model: "m", BaseURL: "http://127.0.0.1:8080/v1"},
		{Provider: "anthropic", APIKey: "k"}, // default base is https
	}
	for _, s := range ok {
		if _, err := NewProvider(s); err != nil {
			t.Errorf("NewProvider(%s, %q) errored: %v", s.Provider, s.BaseURL, err)
		}
	}
}

// Non-2xx responses must surface as errors, not be parsed as success.
func TestProviderHTTPErrorSurfaces(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, `{"error":"bad key"}`)
	}))
	defer srv.Close()
	p, _ := NewProvider(Settings{Provider: "anthropic", APIKey: "k", BaseURL: srv.URL})
	_, err := p.Summarize(context.Background(), "s", "u")
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Errorf("expected 401 error, got %v", err)
	}
}
