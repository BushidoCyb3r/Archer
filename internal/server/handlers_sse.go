package server

import "net/http"

func (s *Server) handleSSE(w http.ResponseWriter, r *http.Request) {
	s.broker.ServeHTTP(w, r)
}
