package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"database/sql"
	"github.com/BushidoCyb3r/Archer/internal/config"
	"github.com/BushidoCyb3r/Archer/internal/feeds"
	"github.com/BushidoCyb3r/Archer/internal/model"
	"github.com/BushidoCyb3r/Archer/internal/store"
	_ "modernc.org/sqlite"
)

// newFeedsTestServer builds a Server backed by a fresh on-disk
// SQLite database (modernc.org/sqlite). The feed handlers exercise
// the store + worker plumbing we built in slices 1-4, so a real DB
// is needed instead of an in-memory mock.
func newFeedsTestServer(t *testing.T) *Server {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open test DB: %v", err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	if err := store.RunMigrations(db); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}
	st := store.New(config.Default())
	st.InitDB(db)
	return &Server{store: st, broker: NewBroker()}
}

// withUser injects an authenticated user into a request's context,
// bypassing requireAuth/requireRole middleware so handler tests can
// hit admin-only paths directly.
func withUser(req *http.Request, role string) *http.Request {
	user := model.User{ID: 1, Email: "test@example.test", Role: role}
	return req.WithContext(context.WithValue(req.Context(), ctxUser, user))
}

func TestHandleFeeds_GET_Empty(t *testing.T) {
	s := newFeedsTestServer(t)
	req := withUser(httptest.NewRequest(http.MethodGet, "/api/feeds", nil), model.RoleViewer)
	w := httptest.NewRecorder()
	s.handleFeeds(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Feeds []feedResponse `json:"feeds"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Feeds) != 0 {
		t.Errorf("expected empty feeds list, got %+v", resp.Feeds)
	}
}

func TestHandleFeeds_POST_RequiresAdmin(t *testing.T) {
	s := newFeedsTestServer(t)
	body, _ := json.Marshal(feedRequest{
		SourceType: "misp", Name: "f", URL: "https://x.test", APIKey: "k",
		RefreshCadenceMinutes: 60, IndicatorAgingDays: 30, Enabled: true,
	})
	req := withUser(httptest.NewRequest(http.MethodPost, "/api/feeds", bytes.NewReader(body)), model.RoleAnalyst)
	w := httptest.NewRecorder()
	s.handleFeeds(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("non-admin POST should 403, got %d", w.Code)
	}
}

func TestHandleFeeds_POST_CreatesFeed(t *testing.T) {
	s := newFeedsTestServer(t)
	body, _ := json.Marshal(feedRequest{
		SourceType:            "misp",
		Name:                  "test-misp",
		URL:                   "https://misp.example.test",
		APIKey:                "secret-key",
		RefreshCadenceMinutes: 60,
		IndicatorAgingDays:    30,
		Enabled:               true,
	})
	req := withUser(httptest.NewRequest(http.MethodPost, "/api/feeds", bytes.NewReader(body)), model.RoleAdmin)
	w := httptest.NewRecorder()
	s.handleFeeds(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; body: %s", w.Code, w.Body.String())
	}
	var resp struct {
		ID int64 `json:"id"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.ID == 0 {
		t.Fatalf("expected non-zero id in response: %s", w.Body.String())
	}

	// Verify the feed landed in the store with the API key persisted
	// but NOT echoed in any GET response.
	got, err := s.store.GetFeed(resp.ID)
	if err != nil {
		t.Fatalf("GetFeed: %v", err)
	}
	if got.APIKey != "secret-key" {
		t.Errorf("APIKey = %q, want %q", got.APIKey, "secret-key")
	}

	// GET should redact api_key.
	getReq := withUser(httptest.NewRequest(http.MethodGet, "/api/feeds", nil), model.RoleViewer)
	getW := httptest.NewRecorder()
	s.handleFeeds(getW, getReq)
	if !json.Valid(getW.Body.Bytes()) {
		t.Fatalf("GET body not valid JSON: %s", getW.Body.String())
	}
	if bytes.Contains(getW.Body.Bytes(), []byte("secret-key")) {
		t.Errorf("GET /api/feeds leaked the API key in body: %s", getW.Body.String())
	}
}

func TestHandleFeeds_POST_RejectsInvalid(t *testing.T) {
	s := newFeedsTestServer(t)
	tests := []struct {
		name string
		req  feedRequest
	}{
		{"empty source_type", feedRequest{Name: "n", URL: "https://x.test", APIKey: "k", RefreshCadenceMinutes: 60}},
		{"unknown source_type", feedRequest{SourceType: "stix", Name: "n", URL: "https://x.test", APIKey: "k", RefreshCadenceMinutes: 60}},
		{"empty name", feedRequest{SourceType: "misp", URL: "https://x.test", APIKey: "k", RefreshCadenceMinutes: 60}},
		{"empty url", feedRequest{SourceType: "misp", Name: "n", APIKey: "k", RefreshCadenceMinutes: 60}},
		{"url no scheme", feedRequest{SourceType: "misp", Name: "n", URL: "x.test", APIKey: "k", RefreshCadenceMinutes: 60}},
		{"empty api_key on create", feedRequest{SourceType: "misp", Name: "n", URL: "https://x.test", RefreshCadenceMinutes: 60}},
		{"zero cadence", feedRequest{SourceType: "misp", Name: "n", URL: "https://x.test", APIKey: "k"}},
		{"negative aging", feedRequest{SourceType: "misp", Name: "n", URL: "https://x.test", APIKey: "k", RefreshCadenceMinutes: 60, IndicatorAgingDays: -1}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := json.Marshal(tt.req)
			req := withUser(httptest.NewRequest(http.MethodPost, "/api/feeds", bytes.NewReader(body)), model.RoleAdmin)
			w := httptest.NewRecorder()
			s.handleFeeds(w, req)
			if w.Code != http.StatusBadRequest {
				t.Errorf("expected 400; got %d (body: %s)", w.Code, w.Body.String())
			}
		})
	}
}

func TestHandleFeedItem_PUT_PreservesAPIKeyOnEmptyField(t *testing.T) {
	s := newFeedsTestServer(t)
	id, err := s.store.CreateFeed(feeds.Feed{
		SourceType: feeds.SourceMISP, Name: "f", URL: "https://x.test",
		APIKey: "original-key", RefreshCadenceMinutes: 60, IndicatorAgingDays: 30, Enabled: true,
	})
	if err != nil {
		t.Fatalf("CreateFeed: %v", err)
	}

	// PUT with api_key omitted ("") should keep the original.
	body, _ := json.Marshal(feedRequest{
		SourceType:            "misp",
		Name:                  "f-renamed",
		URL:                   "https://x.test",
		APIKey:                "",
		RefreshCadenceMinutes: 30,
		IndicatorAgingDays:    7,
		Enabled:               true,
	})
	req := withUser(httptest.NewRequest(http.MethodPut, "/api/feeds/1", bytes.NewReader(body)), model.RoleAdmin)
	w := httptest.NewRecorder()
	s.handleFeedItem(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("PUT status = %d; body: %s", w.Code, w.Body.String())
	}

	got, _ := s.store.GetFeed(id)
	if got.APIKey != "original-key" {
		t.Errorf("APIKey was overwritten: got %q, want %q", got.APIKey, "original-key")
	}
	if got.Name != "f-renamed" {
		t.Errorf("Name not updated: %q", got.Name)
	}
	if got.RefreshCadenceMinutes != 30 {
		t.Errorf("cadence not updated: %d", got.RefreshCadenceMinutes)
	}
}

func TestHandleFeedItem_DELETE(t *testing.T) {
	s := newFeedsTestServer(t)
	id, _ := s.store.CreateFeed(feeds.Feed{
		SourceType: feeds.SourceMISP, Name: "f", URL: "https://x.test",
		APIKey: "k", RefreshCadenceMinutes: 60, Enabled: true,
	})

	req := withUser(httptest.NewRequest(http.MethodDelete, "/api/feeds/1", nil), model.RoleAdmin)
	w := httptest.NewRecorder()
	s.handleFeedItem(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("DELETE status = %d; body: %s", w.Code, w.Body.String())
	}

	if _, err := s.store.GetFeed(id); err == nil {
		t.Errorf("feed still exists after DELETE")
	}
}

func TestHandleFeedRefresh_RejectsDisabledFeed(t *testing.T) {
	s := newFeedsTestServer(t)
	_, _ = s.store.CreateFeed(feeds.Feed{
		SourceType: feeds.SourceMISP, Name: "f", URL: "https://x.test",
		APIKey: "k", RefreshCadenceMinutes: 60, Enabled: false,
	})
	req := withUser(httptest.NewRequest(http.MethodPost, "/api/feeds/1/refresh", nil), model.RoleAdmin)
	w := httptest.NewRecorder()
	s.handleFeedItem(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("disabled feed refresh should 400, got %d (body: %s)", w.Code, w.Body.String())
	}
}

func TestHandleFeedItem_BadID(t *testing.T) {
	s := newFeedsTestServer(t)
	req := withUser(httptest.NewRequest(http.MethodPut, "/api/feeds/abc", bytes.NewReader([]byte("{}"))), model.RoleAdmin)
	w := httptest.NewRecorder()
	s.handleFeedItem(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("non-numeric id should 400, got %d", w.Code)
	}
}
