package initialize

import (
	"errors"
	"flag"
	"fmt"
	"os"
)

func Parse(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	var reset bool
	fs.BoolVar(&reset, "reset", false, "clear all state and reinitialize")

	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: sectool init <mode> [options]

Initialize working directory for agent work.

Modes:
  test-report  Create guide for validating a known issue or bug bounty report
  explore      Create guide for exploring a feature or web app for security flaws

Options:
`)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	remaining := fs.Args()
	if len(remaining) < 1 {
		fs.Usage()
		return errors.New("mode required: test-report or explore")
	}

	mode := remaining[0]
	switch mode {
	case "test-report", "explore":
		return run(mode, reset)
	default:
		return fmt.Errorf("unknown init mode: %s (expected test-report or explore)", mode)
	}
}
