// Package llm provides optional AI enrichment of findings: it takes the
// evidence already collected for a finding (detector output + TI notes) and
// asks a configured large-language-model provider to synthesize a short
// analyst triage briefing. It is annotation-only — nothing here feeds a
// finding's score or severity.
//
// Four operator-facing providers are supported, collapsed onto three wire
// implementations: Anthropic (Claude) and Google (Gemini) have bespoke
// shapes; OpenAI, Ollama, and any other OpenAI-compatible endpoint (LM
// Studio, vLLM, LocalAI) share one /v1/chat/completions implementation that
// varies only by base URL and key. Ollama is the air-gap answer — point it
// at a model running on the local/LAN network and no finding context leaves
// the enclave.
package llm

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

// maxResponseBytes bounds every provider's response read. These are triage
// briefings, not documents; a misbehaving or hostile endpoint must not be
// able to balloon memory. Mirrors the LimitReader discipline the TI
// escalation path uses.
const maxResponseBytes = 1 << 20 // 1 MiB

// maxOutputTokens caps the generated briefing. Kept small deliberately — the
// result is written into a finding note, so it must stay scannable.
const maxOutputTokens = 1024

// defaultTimeout is used when Settings.TimeoutSec is 0.
const defaultTimeout = 30 * time.Second

// ErrRefused is returned when a provider's safety layer declines the request
// (e.g. Anthropic's classifiers on a security-tooling prompt). The caller
// surfaces this distinctly so the analyst knows the model declined rather
// than failed.
var ErrRefused = errors.New("llm: provider declined the request")

// Settings is the provider-agnostic configuration the server maps from
// config.Config. Keeping it local to this package leaves llm free of any
// dependency on internal/config.
type Settings struct {
	Provider   string // "anthropic" | "gemini" | "openai" | "ollama" | "dod" | "custom"
	BaseURL    string // required for ollama/custom; provider default otherwise
	Model      string // required except anthropic, which defaults
	APIKey     string // secret; required for anthropic/gemini/openai
	TimeoutSec int    // 0 = defaultTimeout
}

// Provider is one configured LLM backend. Summarize sends a system prompt and
// a user message (the assembled, already-redacted evidence) and returns the
// model's text. It returns ErrRefused if the provider's safety layer declined.
type Provider interface {
	Name() string
	Summarize(ctx context.Context, system, user string) (string, error)
}

// NewProvider builds a Provider from Settings, applying per-provider defaults
// and validating that the required fields for that provider are present. It
// does not make a network call — validation is structural only.
func NewProvider(s Settings) (Provider, error) {
	timeout := defaultTimeout
	if s.TimeoutSec > 0 {
		timeout = time.Duration(s.TimeoutSec) * time.Second
	}
	switch strings.ToLower(strings.TrimSpace(s.Provider)) {
	case "anthropic":
		if s.APIKey == "" {
			return nil, errors.New("anthropic provider requires an API key")
		}
		model := s.Model
		if model == "" {
			model = "claude-opus-4-8"
		}
		base := s.BaseURL
		if base == "" {
			base = "https://api.anthropic.com"
		} else if err := requireHTTPS("anthropic", base); err != nil {
			return nil, err
		}
		return &anthropicProvider{key: s.APIKey, model: model, base: strings.TrimRight(base, "/"), timeout: timeout}, nil
	case "gemini":
		if s.APIKey == "" {
			return nil, errors.New("gemini provider requires an API key")
		}
		if s.Model == "" {
			return nil, errors.New("gemini provider requires a model name")
		}
		base := s.BaseURL
		if base == "" {
			base = "https://generativelanguage.googleapis.com"
		} else if err := requireHTTPS("gemini", base); err != nil {
			return nil, err
		}
		return &geminiProvider{key: s.APIKey, model: s.Model, base: strings.TrimRight(base, "/"), timeout: timeout}, nil
	case "openai":
		if s.APIKey == "" {
			return nil, errors.New("openai provider requires an API key")
		}
		if s.Model == "" {
			return nil, errors.New("openai provider requires a model name")
		}
		base := s.BaseURL
		if base == "" {
			base = "https://api.openai.com/v1"
		} else if err := requireHTTPS("openai", base); err != nil {
			return nil, err
		}
		return &openAICompatProvider{name: "openai", key: s.APIKey, model: s.Model, base: strings.TrimRight(base, "/"), timeout: timeout}, nil
	case "ollama", "custom", "dod":
		// Self-hosted / enclave OpenAI-compatible endpoints sharing one wire
		// implementation:
		//   ollama — a model on the local/LAN network (air-gapped posture).
		//   dod    — the US DoD GenAI platform reached inside the accredited
		//            boundary (NIPRNet-class); frontier-grade synthesis where
		//            the evidence never leaves the accredited network.
		//   custom — any other OpenAI-compatible gateway.
		// Base URL is required (no sensible default host); the key is optional
		// (Ollama needs none; some enclave gateways authenticate at the
		// network/PKI layer rather than with a bearer token). The "dod"
		// gateways observed in the field speak this wire format with an
		// Authorization: Bearer token — if a specific endpoint uses a
		// different auth header or client-cert/PKI, that's a localized change
		// to the openAICompatProvider, not a new signing path.
		name := strings.ToLower(s.Provider)
		if s.BaseURL == "" {
			return nil, fmt.Errorf("%s provider requires a base URL (e.g. http://host:11434/v1)", name)
		}
		if s.Model == "" {
			return nil, fmt.Errorf("%s provider requires a model name", name)
		}
		return &openAICompatProvider{name: name, key: s.APIKey, model: s.Model, base: strings.TrimRight(s.BaseURL, "/"), timeout: timeout}, nil
	default:
		return nil, fmt.Errorf("unknown LLM provider %q", s.Provider)
	}
}

// requireHTTPS rejects a cleartext base URL for a cloud provider — sending an
// API key and the finding evidence over http to a third-party endpoint would
// expose both on the wire. Loopback is exempt (a local TLS-terminating proxy is
// a legitimate pattern and cleartext to loopback never leaves the host); the
// self-hosted providers (ollama/dod/custom) skip this check entirely, since they
// legitimately run http on a trusted local/enclave network.
func requireHTTPS(provider, base string) error {
	u, err := url.Parse(strings.TrimSpace(base))
	if err != nil {
		return fmt.Errorf("%s provider base URL is invalid: %w", provider, err)
	}
	if strings.EqualFold(u.Scheme, "https") {
		return nil
	}
	if strings.EqualFold(u.Scheme, "http") && isLoopbackHost(u.Hostname()) {
		return nil
	}
	return fmt.Errorf("%s provider base URL must use https (got %q)", provider, base)
}

func isLoopbackHost(h string) bool {
	if strings.EqualFold(h, "localhost") {
		return true
	}
	if ip := net.ParseIP(h); ip != nil {
		return ip.IsLoopback()
	}
	return false
}
