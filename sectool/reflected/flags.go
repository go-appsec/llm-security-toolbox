package reflected

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/pflag"
)

// Parse handles the "sectool reflected" command.
func Parse(args []string, mcpURL string) error {
	fs := pflag.NewFlagSet("reflected", pflag.ContinueOnError)

	fs.Usage = func() {
		_, _ = fmt.Fprint(os.Stderr, `Usage: sectool reflected <flow_id>

Detect request parameter values reflected in the response.

Extracts parameters from the request (query, body, cookies, headers)
and searches the response for each value using multiple encodings.

Arguments:
  <flow_id>    Flow ID (from proxy, replay, or crawl)

Examples:
  sectool reflected f7k2x
  sectool reflected rpl_abc
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	posArgs := fs.Args()
	if len(posArgs) < 1 {
		fs.Usage()
		return errors.New("flow_id required: sectool reflected <flow_id>")
	}

	return run(mcpURL, posArgs[0])
}
