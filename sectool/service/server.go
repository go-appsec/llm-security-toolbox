package service

import (
	"errors"
	"fmt"
)

type Server struct {
	workDir    string
	burpMCPURL string
}

func NewServer(flags DaemonFlags) (*Server, error) {
	if flags.WorkDir == "" {
		return nil, errors.New("workdir is required for service mode")
	}
	return &Server{workDir: flags.WorkDir, burpMCPURL: flags.BurpMCPURL}, nil
}

func (s *Server) Run() error {
	fmt.Printf("sectool service starting: workdir=%s burp_mcp=%s\n", s.workDir, s.burpMCPURL)
	return errors.New("not implemented: service run")
}
