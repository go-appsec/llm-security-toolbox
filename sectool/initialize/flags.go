package initialize

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/pflag"

	"github.com/jentfoo/llm-security-toolbox/sectool/cli"
)

var initModes = []string{"test-report", "explore", "help"}

func Parse(args []string) error {
	fs := pflag.NewFlagSet("init", pflag.ContinueOnError)
	fs.SetInterspersed(true)
	var reset bool
	fs.BoolVar(&reset, "reset", false, "clear all state and reinitialize")

	fs.Usage = func() {
		_, _ = fmt.Fprint(os.Stderr, `Usage: sectool init <mode> [options]

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
	if len(remaining) == 0 {
		fs.Usage()
		return errors.New("mode required: test-report or explore")
	}

	mode := remaining[0]
	switch mode {
	case "test-report", "explore":
		return run(mode, reset)
	case "help", "--help", "-h":
		fs.Usage()
		return nil
	default:
		return cli.UnknownModeError("init", mode, initModes)
	}
}
