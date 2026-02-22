package server

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/miuponn/butler-hub/internal/auth"
	"github.com/miuponn/butler-hub/internal/graph"
	"golang.org/x/oauth2"
)

// server struct to initiate the server and handle routes
type Server struct {
	AuthClient auth.Client
	Token      *oauth2.Token
}

func NewServer(authClient auth.Client) *Server {
	return &Server{
		AuthClient: authClient,
	}
}

func (s *Server) HandleLogin(w http.ResponseWriter, r *http.Request) {
	authURL := s.AuthClient.GetAuthURL()
	http.Redirect(w, r, authURL, http.StatusFound)
}

// handler for OAuth callback, exchanges code for token, initializes Graph client
func (s *Server) HandleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Code not found in query parameters", http.StatusBadRequest)
		return
	}
	token, err := s.AuthClient.HandleCallback(code)
	if err != nil {
		http.Error(w, "Failed to handle callback", http.StatusInternalServerError)
		return
	}
	// store token in server
	s.Token = token
	fmt.Fprintf(w, "Login successful!")
}

// handler to fetch messages from Graph API using stored token
func (s *Server) HandleGetMessages(w http.ResponseWriter, r *http.Request) {
	if s.Token == nil {
		http.Error(w, "User not authenticated", http.StatusUnauthorized)
		return
	}
	graphClient := graph.NewClient(s.Token)
	// fetch messages using graphClient
	messages, _, err := graphClient.GetMessages(graph.QueryOptions{})
	if err != nil {
		http.Error(w, "Failed to fetch messages", http.StatusInternalServerError)
		return
	}
	// return messages as JSON response
	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(messages)
	if err != nil {
		http.Error(w, "Failed to encode messages", http.StatusInternalServerError)
		return
	}
}
