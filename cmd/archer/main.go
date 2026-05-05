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

	"github.com/BushidoCyb3r/Archer/internal/config"
	"github.com/BushidoCyb3r/Archer/internal/server"
	"github.com/BushidoCyb3r/Archer/internal/store"
)

func main() {
	addr     := flag.String("addr", ":8080", "plain HTTP listen address (analyst UI)")
	tlsAddr  := flag.String("tls-addr", ":8443", "HTTPS listen address (Quiver sensor traffic); empty disables")
	tlsDir   := flag.String("tls-dir", "", "directory holding server.crt/server.key (default: <data-dir>/tls)")
	webDir   := flag.String("web-dir", "", "path to web directory (default: ./web next to binary)")
	logsDir  := flag.String("logs-dir", "/logs", "Zeek logs directory (bind-mounted in Docker)")
	dataDir  := flag.String("data-dir", "/data", "persistent data directory (SQLite database)")
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

	cfg    := config.Default()
	st     := store.New(cfg)
	us     := store.NewUserStore(*dataDir)
	st.InitDB(us.DB())
	broker := server.NewBroker()
	srv    := server.New(st, us, broker, *webDir, *logsDir, *authKeys)

	// Bootstrap TLS for sensor-facing traffic. A single bad cert shouldn't
	// take Archer down — the analyst UI on plain HTTP keeps working even
	// when TLS init fails, so we log and continue rather than os.Exit.
	if *tlsAddr != "" {
		if *tlsDir == "" {
			*tlsDir = filepath.Join(*dataDir, "tls")
		}
		certPath, keyPath, fp, err := server.EnsureTLS(*tlsDir)
		if err != nil {
			log.Printf("TLS bootstrap failed (HTTPS disabled): %v", err)
		} else {
			srv.SetTLSFingerprint(fp)
			go func() {
				log.Printf("Archer HTTPS listening on %s  (cert fingerprint sha256//%s)", *tlsAddr, fp)
				if err := http.ListenAndServeTLS(*tlsAddr, certPath, keyPath, srv); err != nil {
					log.Printf("HTTPS listener exited: %v", err)
				}
			}()
		}
	}

	log.Printf("Archer HTTP listening on %s  (web: %s  logs: %s)", *addr, *webDir, *logsDir)
	if err := http.ListenAndServe(*addr, srv); err != nil {
		log.Fatal(err)
	}
}
