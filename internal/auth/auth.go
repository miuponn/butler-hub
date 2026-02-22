package auth

import (
	"context"

	"github.com/miuponn/butler-hub/internal/config"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/microsoft"
)

// Client to handle Microsoft Azure AD authentication
type Client struct {
	Config      config.Config
	OAuthConfig oauth2.Config
}

func NewClient(cfg config.Config) Client {
	oauthConfig := oauth2.Config{
		ClientID:     cfg.AzureClientID,
		ClientSecret: cfg.AzureClientSecret,
		RedirectURL:  cfg.AzureRedirectURL,
		Endpoint:     microsoft.AzureADEndpoint("common"),
		Scopes:       []string{"https://graph.microsoft.com/Mail.ReadWrite", "https://graph.microsoft.com/User.Read"},
	}
	return Client{
		Config:      cfg,
		OAuthConfig: oauthConfig,
	}
}

func (c Client) GetAuthURL() string {
	authURL := c.OAuthConfig.AuthCodeURL("state")
	return authURL
}

func (c Client) HandleCallback(code string) (*oauth2.Token, error) {
	ctx := context.Background()
	token, err := c.OAuthConfig.Exchange(ctx, code)
	if err != nil {
		return nil, err
	}
	return token, nil
}
