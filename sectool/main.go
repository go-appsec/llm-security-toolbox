package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/jentfoo/llm-security-toolbox/sectool/config"
	"github.com/jentfoo/llm-security-toolbox/sectool/encode"
	"github.com/jentfoo/llm-security-toolbox/sectool/initialize"
	"github.com/jentfoo/llm-security-toolbox/sectool/oast"
	"github.com/jentfoo/llm-security-toolbox/sectool/proxy"
	"github.com/jentfoo/llm-security-toolbox/sectool/replay"
	"github.com/jentfoo/llm-security-toolbox/sectool/service"
)

func main() {
	args := os.Args[1:]
	if len(args) > 0 && args[0] == "--service" {
		os.Exit(runServiceMode(args[1:]))
		return
	}

	os.Exit(runClientCLI(args))
}

func runServiceMode(args []string) int {
	flags, err := service.ParseDaemonFlags(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing service flags: %v\n", err)
		return 1
	}

	if srv, err := service.NewServer(flags); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating service: %v\n", err)
		return 1
	} else if err := srv.Run(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "Service error: %v\n", err)
		return 1
	}
	return 0
}

func runClientCLI(args []string) int {
	if len(args) < 1 {
		printRootUsage()
		return 1
	}

	var err error
	switch args[0] {
	case "init":
		err = initialize.Parse(args[1:])
	case "service":
		err = service.Parse(args[1:])
	case "proxy":
		err = proxy.Parse(args[1:])
	case "replay":
		err = replay.Parse(args[1:])
	case "oast":
		err = oast.Parse(args[1:])
	case "encode":
		err = encode.Parse(args[1:])
	case "version", "--version", "-v":
		fmt.Printf("sectool version %s\n", config.Version)
		return 0
	case "help", "--help", "-h":
		printRootUsage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", args[0])
		printRootUsage()
		return 1
	}

	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}
	return 0
}

func printRootUsage() {
	fmt.Fprint(os.Stderr, `Usage: sectool <command> [options]

Commands:
  init       Initialize working directory for security agent task
  service    Manage the sectool service (status, stop, logs)
  proxy      Query and manage proxy history
  replay     Replay HTTP requests (with validation)
  oast       Manage OAST domains for out-of-band testing
  encode     Encoding/decoding utilities (url, base64, html)

Global Options:
  --timeout <dur>    Client-side timeout (default: 30s)

Use "sectool <command> --help" for specific command usage.
`)
}
