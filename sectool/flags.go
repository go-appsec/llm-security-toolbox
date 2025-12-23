package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/jentfoo/llm-security-toolbox/sectool/encode"
	"github.com/jentfoo/llm-security-toolbox/sectool/initialize"
	"github.com/jentfoo/llm-security-toolbox/sectool/oast"
	"github.com/jentfoo/llm-security-toolbox/sectool/proxy"
	"github.com/jentfoo/llm-security-toolbox/sectool/replay"
	"github.com/jentfoo/llm-security-toolbox/sectool/service"
)

func Run(args []string) int {
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
		fmt.Printf("sectool version %s\n", Version)
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
  init       Initialize working directory for agent work
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
