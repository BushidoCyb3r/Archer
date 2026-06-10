package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/BushidoCyb3r/Archer/internal/config"
	"github.com/BushidoCyb3r/Archer/internal/model"
	"github.com/BushidoCyb3r/Archer/internal/store"
)

// TestHandleNotifications_ViewerCannotDismiss is the S-2 regression.
// Notifications are store-global, so a read-only viewer dismissing them would
// clear live CRITICAL / TI / unauthorized-sensor alerts for every analyst.
// POST (dismiss / dismiss_all) is a write action and must be forbidden for
// viewers; GET stays open so viewers can still read the bell. Write roles
// dismiss as before.
func TestHandleNotifications_ViewerCannotDismiss(t *testing.T) {
	st := store.New(config.Default())
	n := st.AddAlarm(model.Notification{Kind: "sensor", Detail: "unauthorized sensor attempt"})
	s := &Server{store: st, broker: NewBroker()}

	dismissed := func() bool {
		for _, x := range st.GetNotifications() {
			if x.ID == n.ID {
				return x.Dismissed
			}
		}
		t.Fatalf("notification %d vanished", n.ID)
		return false
	}

	post := func(role string) *httptest.ResponseRecorder {
		body := strings.NewReader(`{"action":"dismiss_all"}`)
		req := withUser(httptest.NewRequest(http.MethodPost, "/api/notifications", body), role)
		w := httptest.NewRecorder()
		s.handleNotifications(w, req)
		return w
	}

	// Viewer is forbidden and the alert survives.
	if w := post(model.RoleViewer); w.Code != http.StatusForbidden {
		t.Errorf("viewer dismiss_all: status = %d, want 403", w.Code)
	}
	if dismissed() {
		t.Error("viewer dismiss_all cleared the alert — it must not")
	}

	// Viewer can still read notifications.
	getReq := withUser(httptest.NewRequest(http.MethodGet, "/api/notifications", nil), model.RoleViewer)
	getW := httptest.NewRecorder()
	s.handleNotifications(getW, getReq)
	if getW.Code != http.StatusOK {
		t.Errorf("viewer GET notifications: status = %d, want 200", getW.Code)
	}

	// Analyst dismisses successfully.
	if w := post(model.RoleAnalyst); w.Code != http.StatusOK {
		t.Errorf("analyst dismiss_all: status = %d, want 200", w.Code)
	}
	if !dismissed() {
		t.Error("analyst dismiss_all did not clear the alert")
	}
}
