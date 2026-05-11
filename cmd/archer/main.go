package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/BushidoCyb3r/Archer/internal/config"
	"github.com/BushidoCyb3r/Archer/internal/server"
	"github.com/BushidoCyb3r/Archer/internal/store"
)

func main() {
	// Single TLS listener for everyone — admins, analysts, viewers,
	// AND sensors. Pre-v0.14.5 Archer ran a plain HTTP listener on
	// :8080 for the UI and a TLS listener on :8443 for sensors;
	// every user role logged in over cleartext on :8080,
	// transmitting passwords and session cookies in the clear over
	// the LAN Archer was deployed to monitor. The plaintext path
	// was removed entirely in v0.14.5 (NEW-49). The unified TLS
	// listener has no concurrency concerns — sensor heartbeat
	// traffic is ~0.014 req/sec per 50-sensor fleet, dwarfed by
	// analyst SPA load. Cert pinning on the sensor side still
	// works because pinning checks the public key, not the chain;
	// the operator's CA-signed cert (the documented deployment
	// path in OPERATIONS.md) satisfies both browser chain
	// validation and sensor pinning simultaneously.
	tlsAddr := flag.String("tls-addr", ":8443", "HTTPS listen address (the only listener — every role, including sensors, uses TLS)")
	tlsDir := flag.String("tls-dir", "", "directory holding server.crt/server.key (default: <data-dir>/tls)")
	webDir := flag.String("web-dir", "", "path to web directory (default: ./web next to binary)")
	logsDir := flag.String("logs-dir", "/logs", "Zeek logs directory (bind-mounted in Docker)")
	dataDir := flag.String("data-dir", "/data", "persistent data directory (SQLite database)")
	authKeys := flag.String("authkeys-path", "/home/quiver/.ssh/authorized_keys", "sshd authorized_keys file Archer rewrites on enroll/disenroll")
	flag.Parse()

	// Resolve web directory
	if *webDir == "" {
		exe, _ := os.Executable()
		*webDir = filepath.Join(filepath.Dir(exe), "web")
		// Fallback for `go run`
		if _, err := os.Stat(*webDir); err != nil {
			*webDir = "web"
		}
	}

	// Log any terminating signal with a full goroutine stack dump before exit,
	// so silent container deaths become visible in `docker logs`.
	sigCh := make(chan os.Signal, 4)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP, syscall.SIGQUIT)
	go func() {
		sig := <-sigCh
		buf := make([]byte, 1<<20)
		n := runtime.Stack(buf, true)
		log.Printf("=== received signal %v ===\n%s=== end stack dump ===", sig, buf[:n])
		os.Exit(128 + int(sig.(syscall.Signal)))
	}()

	cfg := config.Default()
	st := store.New(cfg)
	us := store.NewUserStore(*dataDir)
	st.InitDB(us.DB())
	broker := server.NewBroker()
	srv := server.New(st, us, broker, *webDir, *logsDir, *authKeys)

	if *tlsAddr == "" {
		log.Fatal("--tls-addr is required (Archer is HTTPS-only as of v0.14.5; the plaintext :8080 listener was removed in NEW-49)")
	}
	if *tlsDir == "" {
		*tlsDir = filepath.Join(*dataDir, "tls")
	}
	certPath, keyPath, fp, err := server.EnsureTLS(*tlsDir)
	if err != nil {
		// Pre-v0.14.5 a TLS bootstrap failure logged and continued
		// — the plaintext listener was the fallback. There IS no
		// fallback now; admin auth requires TLS, so the only
		// correct response to "we can't bootstrap TLS" is to
		// surface the error and refuse to start.
		log.Fatalf("TLS bootstrap failed: %v", err)
	}
	srv.SetTLSFingerprint(fp)
	log.Printf("Archer HTTPS listening on %s  (cert fingerprint sha256//%s)", *tlsAddr, fp)
	log.Printf("  web: %s  logs: %s", *webDir, *logsDir)

	// Pre-v0.14.9 the HTTPS listener was the bare http.ListenAndServeTLS
	// convenience wrapper, which builds an http.Server with zero
	// timeouts — meaning slowloris-style header drips, half-open
	// idle sockets, and stalled bodies could each hold a goroutine
	// open indefinitely. Concrete operational risk on a small-team
	// deployment is modest (the listener is rarely internet-exposed)
	// but the cost of explicit timeouts is one struct and zero
	// behavioral changes for normal clients.
	//
	// ReadHeaderTimeout (10s) is the slowloris guard — covers the
	// time from accept() to "headers fully received," cheaply
	// short-circuiting bytes-per-second-style attacks. ReadTimeout
	// (30s) bounds the entire request read; the largest legitimate
	// body Archer accepts is the ~16 KB JSON config blob, which any
	// real client transmits in milliseconds. IdleTimeout (120s)
	// closes keep-alive sockets that have gone quiet between
	// requests; the SPA's polling cadence is well inside that
	// window. WriteTimeout is deliberately left at zero — /events
	// SSE streams hold the response open for the analyst's entire
	// session (sometimes hours) and Archer's progress events on
	// long analyses can space minutes apart; a non-zero
	// WriteTimeout would silently terminate those connections.
	// v0.14.9 NEW-64.
	httpSrv := &http.Server{
		Addr:              *tlsAddr,
		Handler:           srv,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	if err := httpSrv.ListenAndServeTLS(certPath, keyPath); err != nil {
		log.Fatal(err)
	}
}
