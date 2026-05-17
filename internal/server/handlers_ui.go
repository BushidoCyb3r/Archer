package server

import (
	"encoding/json"
	"html/template"
	"net/http"
	"path/filepath"
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

	data := map[string]template.JS{
		"ScoreExplanations": template.JS(scoreJSON),
	}

	// Like /static/, the index page is served no-store so a UI redeploy
	// doesn't leave the browser holding a template from before new modal
	// sections (e.g. Pending Tokens) were added.
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = tmpl.Execute(w, data)
}

func scoreExplanationsJS() map[string]string {
	// Import from model package
	from := map[string]string{}
	// Re-export the model constants as a plain map for JS bootstrapping
	for k, v := range scoreExplanationsMap {
		from[k] = v
	}
	return from
}
