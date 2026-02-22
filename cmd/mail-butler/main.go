package main

import (
	"log"
	"net/http"

	"github.com/joho/godotenv"
	"github.com/miuponn/butler-hub/internal/auth"
	"github.com/miuponn/butler-hub/internal/config"
	"github.com/miuponn/butler-hub/internal/server"
)

func main() {
	// load env vars from .env
	if err := godotenv.Load(); err != nil {
		log.Fatal("Error loading .env file")
	}
	// initialize config, auth client, and server
	cfg, err := config.NewConfig()
	if err != nil {
		log.Fatalf("Error loading config: %v", err)
	}

	client := auth.NewClient(cfg)
	srv := server.NewServer(client)

	// redirects for login and OAuth callback
	http.HandleFunc("/auth/login", srv.HandleLogin)
	http.HandleFunc("/auth/callback", srv.HandleCallback)
	http.HandleFunc("/mail/messages", srv.HandleGetMessages)

	log.Fatal(http.ListenAndServe(":8080", nil))

}
