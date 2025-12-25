package oast

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"time"
)

func Parse(args []string) error {
	if len(args) < 1 {
		printUsage()
		return errors.New("subcommand required")
	}

	switch args[0] {
	case "create":
		return parseCreate(args[1:])
	case "poll":
		return parsePoll(args[1:])
	case "list":
		return parseList(args[1:])
	case "delete":
		return parseDelete(args[1:])
	case "help", "--help", "-h":
		printUsage()
		return nil
	default:
		return fmt.Errorf("unknown oast subcommand: %s", args[0])
	}
}

func printUsage() {
	fmt.Fprint(os.Stderr, `Usage: sectool oast <command> [options]

Manage OAST (Out-of-band Application Security Testing) domains.

Commands:
  create     Create a new OAST session
  poll       Poll for interactions (long-poll up to 2 minutes)
  list       List active OAST sessions
  delete     Delete an OAST session

Use "sectool oast <command> --help" for more information.
`)
}

func parseCreate(args []string) error {
	fs := flag.NewFlagSet("oast create", flag.ContinueOnError)
	var timeout time.Duration

	fs.DurationVar(&timeout, "timeout", 30*time.Second, "client-side timeout")

	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: sectool oast create [options]

Create a new OAST session.

Options:
`)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	return create(timeout)
}

func parsePoll(args []string) error {
	fs := flag.NewFlagSet("oast poll", flag.ContinueOnError)
	var timeout, wait time.Duration
	var since string

	fs.DurationVar(&timeout, "timeout", 30*time.Second, "client-side timeout")
	fs.StringVar(&since, "since", "", "filter events since event_id or 'last'")
	fs.DurationVar(&wait, "wait", 120*time.Second, "max wait time for events (max 120s)")

	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: sectool oast poll <oast_id> [options]

Poll for OAST interactions.

Options:
`)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	if len(fs.Args()) < 1 {
		fs.Usage()
		return errors.New("oast_id required")
	}

	return poll(timeout, fs.Args()[0], since, wait)
}

func parseList(args []string) error {
	fs := flag.NewFlagSet("oast list", flag.ContinueOnError)
	var timeout time.Duration

	fs.DurationVar(&timeout, "timeout", 30*time.Second, "client-side timeout")

	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: sectool oast list [options]

List active OAST sessions.

Options:
`)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	return list(timeout)
}

func parseDelete(args []string) error {
	fs := flag.NewFlagSet("oast delete", flag.ContinueOnError)
	var timeout time.Duration

	fs.DurationVar(&timeout, "timeout", 30*time.Second, "client-side timeout")

	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: sectool oast delete <oast_id> [options]

Delete an OAST session.

Options:
`)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return err
	} else if len(fs.Args()) < 1 {
		fs.Usage()
		return errors.New("oast_id required")
	}

	return del(timeout, fs.Args()[0])
}
