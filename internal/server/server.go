package server

import (
	"fmt"
	"net/http"

	"github.com/miuponn/butler-hub/internal/auth"
)

type Server struct {
	AuthClient auth.Client
}

func NewServer(authClient auth.Client) Server {
	return Server{
		AuthClient: authClient,
	}
}

func (s Server) HandleLogin(w http.ResponseWriter, r *http.Request) {
	authURL := s.AuthClient.GetAuthURL()
	http.Redirect(w, r, authURL, http.StatusFound)
}

func (s Server) HandleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Code not found in query parameters", http.StatusBadRequest)
		return
	}
	_, err := s.AuthClient.HandleCallback(code)
	if err != nil {
		http.Error(w, "Failed to handle callback", http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, "Login successful!")
}
