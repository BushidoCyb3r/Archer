package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/BushidoCyb3r/Archer/internal/config"
	"github.com/BushidoCyb3r/Archer/internal/server"
	"github.com/BushidoCyb3r/Archer/internal/store"
)

func main() {
	addr    := flag.String("addr", ":8080", "listen address")
	webDir  := flag.String("web-dir", "", "path to web directory (default: ./web next to binary)")
	logsDir := flag.String("logs-dir", "/logs", "Zeek logs directory (bind-mounted in Docker)")
	dataDir := flag.String("data-dir", "/data", "persistent data directory (SQLite database)")
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

	cfg    := config.Default()
	st     := store.New(cfg)
	us     := store.NewUserStore(*dataDir)
	st.InitDB(us.DB())
	broker := server.NewBroker()
	srv    := server.New(st, us, broker, *webDir, *logsDir)

	log.Printf("Archer listening on %s  (web: %s  logs: %s)", *addr, *webDir, *logsDir)
	if err := http.ListenAndServe(*addr, srv); err != nil {
		log.Fatal(err)
	}
}
