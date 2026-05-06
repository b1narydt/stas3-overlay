package main

import (
	"context"
	"log/slog"
	"os"
	"strconv"

	"github.com/metawatt/stas3-overlay/pkg/stas3"

	"github.com/bsv-blockchain/go-overlay-fiber/pkg/server"
)

func main() {
	slog.SetLogLoggerLevel(slog.LevelInfo)

	privKey := os.Getenv("SERVER_PRIVATE_KEY")
	hostURL := os.Getenv("HOSTING_URL")
	mongoURL := os.Getenv("MONGO_URL")
	sqlDB := envOr("SQL_DB", "./data.db")
	port := envInt("SERVER_PORT", 8080)

	if privKey == "" {
		slog.Error("SERVER_PRIVATE_KEY is required")
		os.Exit(1)
	}
	if hostURL == "" {
		slog.Error("HOSTING_URL is required")
		os.Exit(1)
	}
	if mongoURL == "" {
		slog.Error("MONGO_URL is required")
		os.Exit(1)
	}

	srv := server.NewOverlayServer("stas3-overlay", privKey, hostURL)
	srv.ConfigurePort(port)
	srv.ConfigureDatabase("sqlite3", sqlDB)
	srv.ConfigureMongoDB(mongoURL)

	// Register STAS v3 topic manager and lookup service.
	srv.ConfigureTopicManager(stas3.TopicName, stas3.NewTopicManager())
	lookupSvc := stas3.NewLookupService(srv.MongoDB)
	srv.ConfigureLookupService(stas3.LookupServiceName, lookupSvc)

	// Ensure MongoDB indexes.
	if err := lookupSvc.EnsureIndexes(context.Background()); err != nil {
		slog.Error("Failed to create MongoDB indexes", "error", err)
		os.Exit(1)
	}

	// Optional ARC API key.
	if arcKey := os.Getenv("ARC_API_KEY"); arcKey != "" {
		srv.ConfigureARCAPIKey(arcKey)
	}

	// Optional admin token (auto-generated if not set).
	if token := os.Getenv("ADMIN_TOKEN"); token != "" {
		srv.ConfigureAdminToken(token)
	}

	srv.ConfigureGASPSync(true)
	srv.ConfigureEngine(true)

	slog.Info("starting stas3-overlay",
		"port", port,
		"hosting_url", hostURL,
	)

	if err := srv.Start(); err != nil {
		slog.Error("Failed to start server", "error", err)
		os.Exit(1)
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}
