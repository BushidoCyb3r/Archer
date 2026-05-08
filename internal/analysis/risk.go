package analysis

import (
	"fmt"
	"math"
	"sort"

	"github.com/BushidoCyb3r/Archer/internal/model"
)

// riskWeights maps detection type → contribution to host risk score.
var riskWeights = map[string]int{
	"Beaconing":         30,
	"HTTP Beaconing":    28,
	"Cobalt Strike URI": 40,
	"C2 URI Pattern":    38,
	"Domain Fronting":   32,
	"Malicious JA3":     40,
	"Threat Intel Hit":  35,
	"Data Exfiltration": 25,
	"Lateral Movement":  20,
	"Strobe":            15,
	"Long Connection":   10,
}

func (a *Analyzer) aggregateRisk(_ []string) {
	// Group existing findings by src_ip
	type hostData struct {
		types    map[string]bool
		maxScore int
		firstTS  string
	}
	hosts := make(map[string]*hostData)

	a.mu.RLock()
	for _, f := range a.findings {
		src := f.SrcIP
		if src == "" || src == "(cert)" || src == "(escalation)" || src == "(network)" {
			continue
		}
		hd := hosts[src]
		if hd == nil {
			hd = &hostData{types: make(map[string]bool)}
			hosts[src] = hd
		}
		hd.types[f.Type] = true
		if f.Score > hd.maxScore {
			hd.maxScore = f.Score
		}
		if hd.firstTS == "" && f.Timestamp != "" {
			hd.firstTS = f.Timestamp
		}
	}
	a.mu.RUnlock()

	for src, hd := range hosts {
		composite := 0
		for t := range hd.types {
			if w, ok := riskWeights[t]; ok {
				composite += w
			}
		}
		if composite == 0 {
			continue
		}
		// Apply log-scale damping to avoid very high raw sums
		composite = int(math.Min(float64(composite), 99))

		var sev model.Severity
		switch {
		case composite >= 75:
			sev = model.SevCritical
		case composite >= 50:
			sev = model.SevHigh
		case composite >= 25:
			sev = model.SevMedium
		default:
			sev = model.SevLow
		}

		typeList := make([]string, 0, len(hd.types))
		for t := range hd.types {
			typeList = append(typeList, t)
		}
		sort.Strings(typeList)

		a.add(model.Finding{
			Type:      "Host Risk Score",
			Severity:  sev,
			Score:     composite,
			SrcIP:     src,
			DstIP:     "(network)",
			Detail:    fmt.Sprintf("Composite risk: %d | Detections: %v", composite, typeList),
			Timestamp: hd.firstTS,
		})
	}
}
