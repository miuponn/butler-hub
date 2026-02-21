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
	if err := godotenv.Load(); err != nil {
		log.Fatal("Error loading .env file")
	}
	cfg, err := config.NewConfig()
	if err != nil {
		log.Fatalf("Error loading config: %v", err)
	}

	client := auth.NewClient(cfg)

	server := server.NewServer(client)

	http.HandleFunc("/auth/login", server.HandleLogin)
	http.HandleFunc("/auth/callback", server.HandleCallback)

	log.Fatal(http.ListenAndServe(":8080", nil))

}
