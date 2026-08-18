// patchlight is the Patchlight product binary: CVE prioritisation on Sentinel
// Core.
//
//	patchlight                      # dashboard on 127.0.0.1:8425
//	patchlight -nvd-api-key <key>   # higher NVD rate limit
//	patchlight -kev-url file://...  # air-gapped: point feeds at local mirrors
//
// Add what you run (product+version, raw CPE, or an SBOM), and Patchlight ranks
// the CVEs that affect it by CISA KEV + EPSS + CVSS.
package main

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	_ "github.com/mattn/go-sqlite3" // dev driver; release swaps to modernc.org/sqlite

	"github.com/nizartuanku/patchlight/epss"
	"github.com/nizartuanku/patchlight/kev"
	"github.com/nizartuanku/patchlight/license"
	"github.com/nizartuanku/patchlight/notify"
	"github.com/nizartuanku/patchlight/nvd"
	"github.com/nizartuanku/patchlight/patchlight"
	"github.com/nizartuanku/patchlight/sched"
	"github.com/nizartuanku/patchlight/store"
	"github.com/nizartuanku/patchlight/web"
)

// issuerPublicKeyB64 is baked in at build time by the release process.
// Empty → every key invalid → permanent free edition (this open-source build).
var issuerPublicKeyB64 = ""

// patchlightTierLimits: free = 25 inventory items, Pro = 500, Team = unlimited.
var patchlightTierLimits = map[license.Tier]license.Limits{
	license.TierFree: {MaxTargets: 25, RetentionDays: 30, Channels: []string{"webhook"}},
	license.TierPro: {MaxTargets: 500, RetentionDays: 365,
		Channels: []string{"webhook", "email", "slack", "telegram"}, CustomInterval: true, ScanNow: true},
	license.TierTeam: {MaxTargets: 0, RetentionDays: 0,
		Channels:  []string{"webhook", "email", "slack", "telegram", "pagerduty", "teams"},
		MultiUser: true, CustomInterval: true, ScanNow: true},
}

func main() {
	listen := flag.String("listen", "127.0.0.1:8425", "dashboard listen address")
	dbPath := flag.String("db", "patchlight.db", "SQLite database path")
	licFile := flag.String("license", "patchlight-license.key", "license key file")
	webhook := flag.String("webhook", "", "webhook URL for alerts")
	nvdKey := flag.String("nvd-api-key", "", "NVD API key (raises the rate limit)")
	nvdCVEURL := flag.String("nvd-cve-url", "", "override NVD CVE API base (air-gapped mirror)")
	nvdCPEURL := flag.String("nvd-cpe-url", "", "override NVD CPE dictionary base (air-gapped mirror)")
	kevURL := flag.String("kev-url", "", "override CISA KEV feed URL (air-gapped mirror)")
	epssURL := flag.String("epss-url", "", "override FIRST EPSS API base (air-gapped mirror)")
	flag.Parse()

	db, err := sql.Open("sqlite3", *dbPath)
	if err != nil {
		fatal("open database: " + err.Error())
	}
	st, err := store.NewSQLiteStore(db)
	if err != nil {
		fatal(err.Error())
	}
	engine := store.NewEngine(st)

	fetch := httpFetcher(*nvdKey)
	nvdClient := &nvd.Client{Fetch: fetch, APIKey: *nvdKey, CVEBase: *nvdCVEURL, CPEBase: *nvdCPEURL}
	kevProv := &kev.Provider{Fetch: fetch, FeedURL: *kevURL}
	epssProv := &epss.Provider{Fetch: fetch, APIBase: *epssURL}
	intel := &patchlight.LiveIntel{NVD: nvdClient, KEV: kevProv, EPSS: epssProv}

	module := patchlight.New(intel)
	scheduler := sched.New(engine, sched.Config{})
	if err := scheduler.Register(module); err != nil {
		fatal(err.Error())
	}
	modID := module.Describe().ID

	// Restore saved inventory (CPEs) before Start.
	if saved, err := st.ListSavedTargets(modID); err == nil {
		for _, raw := range saved {
			if _, err := scheduler.AddTarget(modID, raw); err != nil {
				fmt.Fprintf(os.Stderr, "patchlight: skipping saved item %q: %v\n", raw, err)
			}
		}
	}

	var pub ed25519.PublicKey
	if issuerPublicKeyB64 != "" {
		if b, err := base64.StdEncoding.DecodeString(issuerPublicKeyB64); err == nil {
			pub = ed25519.PublicKey(b)
		}
	}
	server := web.NewServer(module.Describe(), st, scheduler, pub, *licFile)
	server.Targets = st
	server.TierLimits = patchlightTierLimits

	console := &patchlight.Console{
		Resolver: nvdClient.Resolve,
		Add: func(canonical, _ string) error {
			saved, _ := st.ListSavedTargets(modID)
			lim := server.EffectiveLimits()
			if lim.MaxTargets != 0 && len(saved) >= lim.MaxTargets {
				return fmt.Errorf("inventory limit reached (%d items) for your tier — upgrade to add more", lim.MaxTargets)
			}
			if _, err := scheduler.AddTarget(modID, canonical); err != nil {
				return err
			}
			return st.SaveTarget(modID, canonical, canonical)
		},
	}
	server.ExtraRoutes = console.Register

	if *webhook != "" {
		disp := notify.NewDispatcher(notify.Config{}, &notify.WebhookChannel{URL: *webhook})
		notify.BindScheduler(scheduler, disp)
		defer disp.Close()
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := scheduler.Start(ctx); err != nil {
		fatal(err.Error())
	}

	httpSrv := &http.Server{Addr: *listen, Handler: server.Handler()}
	go func() {
		<-ctx.Done()
		sc, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		httpSrv.Shutdown(sc)
		scheduler.Stop()
	}()

	fmt.Printf("Patchlight %s — %s edition\n", module.Describe().Version, server.Activation().Tier)
	fmt.Printf("Dashboard: http://%s\n", *listen)
	if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fatal(err.Error())
	}
}

// httpFetcher returns a Fetcher that GETs a URL, sending the NVD API key header
// when set. Shared by all three feed clients.
func httpFetcher(nvdKey string) func(ctx context.Context, url string) ([]byte, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	return func(ctx context.Context, url string) ([]byte, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "Patchlight/0.1 (self-hosted)")
		if nvdKey != "" {
			req.Header.Set("apiKey", nvdKey)
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 400 {
			return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
		}
		return io.ReadAll(io.LimitReader(resp.Body, 24<<20))
	}
}

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, "patchlight: "+msg)
	os.Exit(1)
}
