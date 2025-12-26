package oast

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/spf13/pflag"

	"github.com/jentfoo/llm-security-toolbox/sectool/cli"
)

var oastSubcommands = []string{"create", "poll", "get", "list", "delete", "help"}

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
	case "get":
		return parseGet(args[1:])
	case "list":
		return parseList(args[1:])
	case "delete":
		return parseDelete(args[1:])
	case "help", "--help", "-h":
		printUsage()
		return nil
	default:
		return cli.UnknownSubcommandError("oast", args[0], oastSubcommands)
	}
}

func printUsage() {
	fmt.Fprint(os.Stderr, `Usage: sectool oast <command> [options]

Manage OAST (Out-of-band Application Security Testing) domains for detecting
blind vulnerabilities (SSRF, XXE, blind SQLi, command injection, etc).

Workflow:
  1. Create a session to get a unique domain:
       sectool oast create
     Returns oast_id and domain (e.g., xyz123.oast.fun)

  2. Use the domain in payloads, with subdomains for tagging:
       curl https://sqli-test.xyz123.oast.fun
       nslookup xxe-probe.xyz123.oast.fun

  3. Poll to see interactions (summary table):
       sectool oast poll <oast_id>
       sectool oast poll <oast_id> --since last    # only new events

  4. Get full details for a specific event:
       sectool oast get <oast_id> <event_id>
     Shows complete raw request/response without truncation

Commands:
  create     Create a new OAST session (returns oast_id and domain)
  poll       Poll for interactions (returns summary table with event_ids)
  get        Get full details for a specific event
  list       List active OAST sessions
  delete     Delete an OAST session

Use "sectool oast <command> --help" for more information.
`)
}

func parseCreate(args []string) error {
	fs := pflag.NewFlagSet("oast create", pflag.ContinueOnError)
	fs.SetInterspersed(true)
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
	fs := pflag.NewFlagSet("oast poll", pflag.ContinueOnError)
	fs.SetInterspersed(true)
	var timeout, wait time.Duration
	var since string

	fs.DurationVar(&timeout, "timeout", 30*time.Second, "client-side timeout")
	fs.StringVar(&since, "since", "", "filter events since event_id or 'last'")
	fs.DurationVar(&wait, "wait", 120*time.Second, "max wait time for events (max 120s)")

	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: sectool oast poll <oast_id> [options]

Poll for OAST interactions. Returns a summary table of events. Use
'sectool oast get' to view full details for a specific event.

Get oast_id from 'sectool oast create' or 'sectool oast list'.

Options:
`)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	if len(fs.Args()) < 1 {
		fs.Usage()
		return errors.New("oast_id required (get from 'sectool oast create' or 'sectool oast list')")
	}

	return poll(timeout, fs.Args()[0], since, wait)
}

func parseGet(args []string) error {
	fs := pflag.NewFlagSet("oast get", pflag.ContinueOnError)
	fs.SetInterspersed(true)
	var timeout time.Duration

	fs.DurationVar(&timeout, "timeout", 30*time.Second, "client-side timeout")

	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: sectool oast get <oast_id> <event_id> [options]

Get full details for a specific OAST event. Use 'sectool oast poll' to list
events and get their event_id values.

This shows the complete raw request/response without truncation, useful for
analyzing the exact payload that triggered an out-of-band interaction.

Options:
`)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	if len(fs.Args()) < 2 {
		fs.Usage()
		return errors.New("oast_id and event_id required (get event_id from 'sectool oast poll')")
	}

	return get(timeout, fs.Args()[0], fs.Args()[1])
}

func parseList(args []string) error {
	fs := pflag.NewFlagSet("oast list", pflag.ContinueOnError)
	fs.SetInterspersed(true)
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
	fs := pflag.NewFlagSet("oast delete", pflag.ContinueOnError)
	fs.SetInterspersed(true)
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
		return errors.New("oast_id required (get from 'sectool oast list')")
	}

	return del(timeout, fs.Args()[0])
}
