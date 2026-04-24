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

	cfg := s.store.GetConfig()
	cfgJSON, _ := json.Marshal(cfg)
	scoreJSON, _ := json.Marshal(scoreExplanationsJS())

	data := map[string]template.JS{
		"Config":            template.JS(cfgJSON),
		"ScoreExplanations": template.JS(scoreJSON),
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
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
