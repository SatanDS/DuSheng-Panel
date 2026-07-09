package main

import (
	"log"

	"dusheng-panel/apps/api/internal/app"
	"dusheng-panel/apps/api/internal/config"
	"dusheng-panel/apps/api/internal/store"
)

func main() {
	cfg := config.FromEnv()

	db, err := store.Open(cfg)
	if err != nil {
		log.Fatalf("open database: %v", err)
	}

	router := app.NewServer(cfg, db)
	log.Printf("DuSheng API listening on %s", cfg.Listen)
	if err := router.Run(cfg.Listen); err != nil {
		log.Fatalf("run api: %v", err)
	}
}
