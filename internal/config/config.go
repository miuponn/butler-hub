package config

import (
	"fmt"
	"os"
)

type Config struct {
	AzureClientID     string
	AzureClientSecret string
	AzureRedirectURL  string
}

func NewConfig() (Config, error) {
	if os.Getenv("AZURE_CLIENT_ID") == "" {
		return Config{}, fmt.Errorf("AZURE_CLIENT_ID is not set")
	}
	if os.Getenv("AZURE_CLIENT_SECRET") == "" {
		return Config{}, fmt.Errorf("AZURE_CLIENT_SECRET is not set")
	}
	if os.Getenv("AZURE_REDIRECT_URL") == "" {
		return Config{}, fmt.Errorf("AZURE_REDIRECT_URL is not set")
	}
	return Config{
		AzureClientID:     os.Getenv("AZURE_CLIENT_ID"),
		AzureClientSecret: os.Getenv("AZURE_CLIENT_SECRET"),
		AzureRedirectURL:  os.Getenv("AZURE_REDIRECT_URL"),
	}, nil
}
