package patchlight

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/nizartuanku/patchlight/cpe"
)

// Console serves Patchlight's inventory-input endpoints: resolve a free-text
// product+version to a CPE and add it, and import an SBOM. Listing and removal
// reuse the framework's standard /api/targets endpoints (a target is just a CPE
// string), so this stays thin: it only does the two things the generic flow
// can't — NVD resolution and SBOM parsing.
//
// The cmd wires Resolver (→ nvd.Resolve) and Add (→ scheduler.AddTarget +
// persist, with the tier's item cap enforced). Add returns an error the handler
// surfaces (e.g. "inventory limit reached").
type Console struct {
	Resolver func(ctx context.Context, product, version string) (cpe.CPE, error)
	Add      func(canonicalCPE, label string) error
}

// Register mounts the console routes.
func (c *Console) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/patchlight/add", c.handleAdd)
	mux.HandleFunc("POST /api/patchlight/sbom", c.handleSBOM)
}

type addRequest struct {
	Product string `json:"product"`
	Version string `json:"version"`
	CPE     string `json:"cpe"` // optional: add a raw CPE directly
}

func (c *Console) handleAdd(w http.ResponseWriter, r *http.Request) {
	var req addRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	var (
		resolved cpe.CPE
		err      error
	)
	if strings.TrimSpace(req.CPE) != "" {
		resolved, err = cpe.Parse(req.CPE)
	} else if strings.TrimSpace(req.Product) != "" {
		resolved, err = c.Resolver(r.Context(), req.Product, req.Version)
	} else {
		httpErr(w, http.StatusBadRequest, "provide a product (and optional version) or a raw cpe")
		return
	}
	if err != nil {
		httpErr(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := c.Add(resolved.Canonical(), resolved.Label()); err != nil {
		httpErr(w, http.StatusForbidden, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"added": resolved.Canonical(),
		"label": resolved.Label(),
	})
}

type sbomResult struct {
	Added     int      `json:"added"`
	Skipped   int      `json:"skipped"`
	Limited   int      `json:"limited"`
	Items     []string `json:"items"`
	FirstError string  `json:"first_error,omitempty"`
}

func (c *Console) handleSBOM(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 8<<20)) // 8 MiB cap
	if err != nil {
		httpErr(w, http.StatusBadRequest, "could not read body")
		return
	}
	comps, err := cpe.ParseSBOM(body)
	if err != nil {
		httpErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(comps) == 0 {
		httpErr(w, http.StatusBadRequest, "no components with usable identifiers found in the SBOM")
		return
	}

	var res sbomResult
	seen := map[string]bool{}
	for _, comp := range comps {
		canon := comp.CPE.Canonical()
		if seen[canon] {
			res.Skipped++
			continue
		}
		seen[canon] = true
		if err := c.Add(canon, comp.CPE.Label()); err != nil {
			res.Limited++
			if res.FirstError == "" {
				res.FirstError = err.Error()
			}
			continue
		}
		res.Added++
		if len(res.Items) < 50 {
			res.Items = append(res.Items, comp.CPE.Label())
		}
	}
	writeJSON(w, http.StatusOK, res)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func httpErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}
