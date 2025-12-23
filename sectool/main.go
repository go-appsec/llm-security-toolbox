package main

import (
	"fmt"
	"os"

	"github.com/jentfoo/llm-security-toolbox/sectool/service"
)

const Version = "0.0.1"

func main() {
	args := os.Args[1:]
	if len(args) > 0 && args[0] == "--service" {
		os.Exit(runServiceMode(args[1:]))
		return
	}

	os.Exit(Run(args)) // TODO - rename Run
}

func runServiceMode(args []string) int {
	flags, err := service.ParseDaemonFlags(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing service flags: %v\n", err)
		return 1
	}

	srv, err := service.NewServer(flags)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating service: %v\n", err)
		return 1
	}

	if err := srv.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Service error: %v\n", err)
		return 1
	}

	return 0
}
