package server

import (
	"encoding/json"
	"html/template"
	"net/http"
	"path/filepath"

	"github.com/BushidoCyb3r/Archer/internal/model"
)

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	tmplPath := filepath.Join(s.webDir, "templates", "index.html")
	tmpl, err := template.ParseFiles(tmplPath)
	if err != nil {
		http.Error(w, "template error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// The config (incl. third-party API keys) is deliberately NOT
	// embedded here: the index page is served to every role, so
	// shipping it in page source disclosed admin-entered credentials
	// to viewers/analysts. The SPA fetches /api/config at runtime,
	// which redacts secrets for non-admins.
	scoreJSON, _ := json.Marshal(scoreExplanationsJS())

	// Finding-type → ATT&CK technique map, bootstrapped into the page so the
	// detail pane and coverage modal render technique tags from a finding's
	// Type without per-finding API bloat. Single source of truth is the Go
	// table (internal/model); same mechanism as ScoreExplanations.
	attackJSON, _ := json.Marshal(model.AttackMap())

	data := map[string]template.JS{
		"ScoreExplanations": template.JS(scoreJSON),
		"AttackMap":         template.JS(attackJSON),
	}

	// Like /static/, the index page is served no-store so a UI redeploy
	// doesn't leave the browser holding a template from before new modal
	// sections (e.g. Pending Tokens) were added.
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = tmpl.Execute(w, data)
}

func scoreExplanationsJS() map[string]model.ScoreExplanation {
	// Re-export the model map for JS bootstrapping. Marshals to
	// {type: {summary, false_positives, scoring}} consumed by detail.js.
	return scoreExplanationsMap
}
