package diff

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/pflag"
)

// Parse handles the "sectool diff" command.
func Parse(args []string, mcpURL string) error {
	fs := pflag.NewFlagSet("diff", pflag.ContinueOnError)
	fs.SetInterspersed(true)

	var scope string
	var maxDiffLines int

	fs.StringVar(&scope, "scope", "", "what to compare: request, response, request_headers, response_headers, request_body, response_body")
	fs.IntVar(&maxDiffLines, "max-diff-lines", 0, "cap body diff output (default: 50 text, 20 JSON)")

	fs.Usage = func() {
		_, _ = fmt.Fprint(os.Stderr, `Usage: sectool diff <flow_a> <flow_b> --scope <scope> [options]

Compare two captured flows, showing exactly what differs.

Arguments:
  <flow_a>    First flow ID (from proxy_poll, replay_send, or crawl_poll)
  <flow_b>    Second flow ID (from any source)

Scope (required):
  request           Method, path, query, request headers, request body
  response          Status, response headers, response body
  request_headers   Method, path, query, request headers only
  response_headers  Status, response headers only
  request_body      Request body only
  response_body     Response body only

Options:
`)
		fs.PrintDefaults()
		_, _ = fmt.Fprint(os.Stderr, `
Examples:
  sectool diff f7k2x rpl_abc --scope response
  sectool diff f7k2x f9m3z --scope request_headers
  sectool diff f7k2x f9m3z --scope request_body --max-diff-lines 100
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	posArgs := fs.Args()
	if len(posArgs) < 2 {
		fs.Usage()
		return errors.New("two flow IDs required: sectool diff <flow_a> <flow_b> --scope <scope>")
	} else if scope == "" {
		fs.Usage()
		return errors.New("--scope is required")
	}

	return run(mcpURL, posArgs[0], posArgs[1], scope, maxDiffLines)
}
