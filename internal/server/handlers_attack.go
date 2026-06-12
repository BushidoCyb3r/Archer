package server

import (
	"encoding/json"
	"net/http"
	"sort"

	"github.com/BushidoCyb3r/Archer/internal/model"
)

// coverageType is one finding type's contribution to a technique (or to the
// unmapped bucket), with its count.
type coverageType struct {
	Type  string `json:"type"`
	Count int    `json:"count"`
}

// coverageTech is one ATT&CK technique with the current finding count behind it
// and the finding types that contributed.
type coverageTech struct {
	ID     string         `json:"id"`
	Name   string         `json:"name"`
	Tactic string         `json:"tactic"`
	URL    string         `json:"url"`
	Count  int            `json:"count"`
	Types  []coverageType `json:"types"`
}

// attackCoverageResult is the /api/attack-coverage payload: techniques the
// current findings evidence (with counts) plus the unmapped finding types, so
// the coverage view shows both what's covered and what isn't. A finding whose
// type maps to N techniques counts toward all N, so technique counts can sum
// past Total — that's coverage, not a partition.
type attackCoverageResult struct {
	Techniques []coverageTech `json:"techniques"`
	Unmapped   []coverageType `json:"unmapped"`
	Total      int            `json:"total"`
}

// attackCoverage rolls a finding set up into ATT&CK technique coverage. Pure
// function (no store / HTTP), so the rollup is unit-testable without plumbing.
func attackCoverage(findings []model.Finding) attackCoverageResult {
	type agg struct {
		tech  model.AttackTechnique
		count int
		types map[string]int
	}
	techAgg := map[string]*agg{}
	unmapped := map[string]int{}

	for _, f := range findings {
		techs := model.AttackTechniquesFor(f.Type)
		if len(techs) == 0 {
			unmapped[f.Type]++
			continue
		}
		for _, tk := range techs {
			a := techAgg[tk.ID]
			if a == nil {
				a = &agg{tech: tk, types: map[string]int{}}
				techAgg[tk.ID] = a
			}
			a.count++
			a.types[f.Type]++
		}
	}

	res := attackCoverageResult{Total: len(findings)}
	for _, a := range techAgg {
		res.Techniques = append(res.Techniques, coverageTech{
			ID:     a.tech.ID,
			Name:   a.tech.Name,
			Tactic: a.tech.Tactic,
			URL:    a.tech.URL(),
			Count:  a.count,
			Types:  sortedCounts(a.types),
		})
	}
	sort.Slice(res.Techniques, func(i, j int) bool {
		if res.Techniques[i].Count != res.Techniques[j].Count {
			return res.Techniques[i].Count > res.Techniques[j].Count
		}
		return res.Techniques[i].ID < res.Techniques[j].ID
	})
	res.Unmapped = sortedCounts(unmapped)
	return res
}

// sortedCounts turns a type→count map into a slice sorted by count desc, then
// name asc for a stable order.
func sortedCounts(m map[string]int) []coverageType {
	out := make([]coverageType, 0, len(m))
	for t, c := range m {
		out = append(out, coverageType{Type: t, Count: c})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Type < out[j].Type
	})
	return out
}

// handleAttackCoverage serves the ATT&CK coverage rollup over the current
// finding set, powering the coverage modal. Read-only; any authenticated role.
func (s *Server) handleAttackCoverage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(attackCoverage(s.store.GetFindings()))
}
