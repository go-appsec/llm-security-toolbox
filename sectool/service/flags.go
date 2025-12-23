package service

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"time"
)

type DaemonFlags struct {
	WorkDir    string
	BurpMCPURL string
}

func ParseDaemonFlags(args []string) (DaemonFlags, error) {
	fs := flag.NewFlagSet("service", flag.ContinueOnError)
	flags := DaemonFlags{BurpMCPURL: "http://127.0.0.1:9876/sse"}

	fs.StringVar(&flags.WorkDir, "workdir", "", "working directory for service state")
	fs.StringVar(&flags.BurpMCPURL, "burp-mcp-url", flags.BurpMCPURL, "Burp MCP SSE endpoint URL")

	if err := fs.Parse(args); err != nil {
		return flags, err
	}

	return flags, nil
}

func Parse(args []string) error {
	if len(args) < 1 {
		printUsage()
		return errors.New("subcommand required")
	}

	switch args[0] {
	case "status":
		return parseStatus(args[1:])
	case "stop":
		return parseStop(args[1:])
	case "logs":
		return parseLogs(args[1:])
	case "help", "--help", "-h":
		printUsage()
		return nil
	default:
		return fmt.Errorf("unknown service subcommand: %s", args[0])
	}
}

func printUsage() {
	fmt.Fprint(os.Stderr, `Usage: sectool service <command> [options]

Manage the sectool background service.

Commands:
  status     Show service status and health
  stop       Stop the running service
  logs       View service logs

Use "sectool service <command> --help" for more information.
`)
}

func parseStatus(args []string) error {
	fs := flag.NewFlagSet("service status", flag.ContinueOnError)
	var timeout time.Duration

	fs.DurationVar(&timeout, "timeout", 30*time.Second, "client-side timeout")

	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: sectool service status [options]

Show service status and health.

Options:
`)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	return status(timeout)
}

func parseStop(args []string) error {
	fs := flag.NewFlagSet("service stop", flag.ContinueOnError)
	var timeout time.Duration

	fs.DurationVar(&timeout, "timeout", 30*time.Second, "client-side timeout")

	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: sectool service stop [options]

Stop the running service.

Options:
`)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	return stop(timeout)
}

func parseLogs(args []string) error {
	fs := flag.NewFlagSet("service logs", flag.ContinueOnError)
	var timeout time.Duration
	var follow bool
	var lines int

	fs.DurationVar(&timeout, "timeout", 30*time.Second, "client-side timeout")
	fs.BoolVar(&follow, "f", false, "follow log output")
	fs.BoolVar(&follow, "follow", false, "follow log output")
	fs.IntVar(&lines, "n", 50, "number of lines to show")
	fs.IntVar(&lines, "lines", 50, "number of lines to show")

	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: sectool service logs [options]

View service logs.

Options:
`)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	return logs(timeout, follow, lines)
}
