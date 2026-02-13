package diff

import (
	"context"
	"fmt"
	"strings"

	"github.com/go-appsec/toolbox/sectool/cliutil"
	"github.com/go-appsec/toolbox/sectool/mcpclient"
	"github.com/go-appsec/toolbox/sectool/protocol"
	"github.com/pmezard/go-difflib/difflib"
)

func run(mcpURL, flowA, flowB, scope string, maxDiffLines int) error {
	ctx := context.Background()

	client, err := mcpclient.Connect(ctx, mcpURL)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	resp, err := client.DiffFlow(ctx, mcpclient.DiffFlowOpts{
		FlowA:        flowA,
		FlowB:        flowB,
		Scope:        scope,
		MaxDiffLines: maxDiffLines,
	})
	if err != nil {
		return fmt.Errorf("diff failed: %w", err)
	}

	fmt.Printf("%s\n\n", cliutil.Bold("Diff Result"))
	fmt.Printf("Comparing %s vs %s (scope: %s)\n\n", cliutil.ID(flowA), cliutil.ID(flowB), scope)

	if resp.Same {
		fmt.Println("Flows are identical (within the selected scope).")
		return nil
	}

	if resp.Request != nil {
		printRequestDiff(resp.Request)
	}
	if resp.Response != nil {
		printResponseDiff(resp.Response)
	}

	return nil
}

func printRequestDiff(d *protocol.RequestDiff) {
	fmt.Printf("%s\n", cliutil.Bold("Request"))

	if d.Method != nil {
		fmt.Printf("  Method: %s → %s\n", d.Method.A, d.Method.B)
	}
	if d.Path != nil {
		fmt.Printf("  Path: %s → %s\n", d.Path.A, d.Path.B)
	}
	if d.Query != nil {
		printParamsDiff("Query", d.Query)
	}
	if d.Headers != nil {
		printParamsDiff("Headers", d.Headers)
	}
	if d.Body != nil {
		printBodyDiff(d.Body)
	}

	fmt.Println()
}

func printResponseDiff(d *protocol.ResponseDiff) {
	fmt.Printf("%s\n", cliutil.Bold("Response"))

	if d.Status != nil {
		fmt.Printf("  Status: %s → %s\n", cliutil.FormatStatus(d.Status.A), cliutil.FormatStatus(d.Status.B))
	}
	if d.Headers != nil {
		printParamsDiff("Headers", d.Headers)
	}
	if d.Body != nil {
		printBodyDiff(d.Body)
	}

	fmt.Println()
}

func printParamsDiff(label string, d *protocol.ParamsDiff) {
	fmt.Printf("\n  %s\n", cliutil.Bold(label))

	for _, a := range d.Added {
		fmt.Printf("    %s %s: %s\n", cliutil.Success("+"), a.Name, a.Value)
	}
	for _, r := range d.Removed {
		fmt.Printf("    %s %s: %s\n", cliutil.Error("-"), r.Name, r.Value)
	}
	for _, c := range d.Changed {
		hlA, hlB := inlineHighlight(c.A, c.B)
		fmt.Printf("    %s %s:\n", cliutil.Warning("~"), c.Name)
		fmt.Printf("      %s %s\n", cliutil.Error("-"), hlA)
		fmt.Printf("      %s %s\n", cliutil.Success("+"), hlB)
	}
	if d.UnchangedCount > 0 {
		fmt.Printf("    %s\n", cliutil.Muted(fmt.Sprintf("(%d unchanged)", d.UnchangedCount)))
	}
}

func printBodyDiff(d *protocol.BodyDiff) {
	switch d.Format {
	case "json":
		fmt.Printf("\n  %s\n", cliutil.Bold("Body (json)"))

		for _, a := range d.Added {
			fmt.Printf("    %s %s: %v\n", cliutil.Success("+"), a.Path, a.Value)
		}
		for _, r := range d.Removed {
			fmt.Printf("    %s %s\n", cliutil.Error("-"), r.Path)
		}
		for _, c := range d.Changed {
			hlA, hlB := inlineHighlight(fmt.Sprintf("%v", c.A), fmt.Sprintf("%v", c.B))
			fmt.Printf("    %s %s:\n", cliutil.Warning("~"), c.Path)
			fmt.Printf("      %s %s\n", cliutil.Error("-"), hlA)
			fmt.Printf("      %s %s\n", cliutil.Success("+"), hlB)
		}
		if d.UnchangedCount > 0 {
			fmt.Printf("    %s\n", cliutil.Muted(fmt.Sprintf("(%d unchanged)", d.UnchangedCount)))
		}
		if d.Truncated {
			fmt.Printf("    %s\n", cliutil.Muted("(truncated)"))
		}

	case "text":
		sizeInfo := ""
		if d.ASize > 0 || d.BSize > 0 {
			sizeInfo = fmt.Sprintf(", %d → %d bytes", d.ASize, d.BSize)
		}
		fmt.Printf("\n  %s\n", cliutil.Bold(fmt.Sprintf("Body (text%s)", sizeInfo)))

		if d.Summary != "" {
			fmt.Printf("    %s\n", d.Summary)
		}
		if d.Diff != "" {
			fmt.Println()
			for _, line := range strings.Split(d.Diff, "\n") {
				fmt.Printf("    %s\n", colorDiffLine(line))
			}
		}
		if d.Truncated {
			fmt.Printf("    %s\n", cliutil.Muted("(truncated)"))
		}

	case "binary":
		sizeInfo := ""
		if d.ASize > 0 || d.BSize > 0 {
			sizeInfo = fmt.Sprintf(", %d → %d bytes", d.ASize, d.BSize)
		}
		fmt.Printf("\n  %s\n", cliutil.Bold(fmt.Sprintf("Body (binary%s)", sizeInfo)))
	}
}

// colorDiffLine applies color to unified diff lines
func colorDiffLine(line string) string {
	if strings.HasPrefix(line, "---") || strings.HasPrefix(line, "+++") || strings.HasPrefix(line, "@@") {
		return cliutil.Muted(line)
	}
	if strings.HasPrefix(line, "+") {
		return cliutil.Success(line)
	}
	if strings.HasPrefix(line, "-") {
		return cliutil.Error(line)
	}
	return line
}

// splitRunes splits a string into per-rune string slices for SequenceMatcher.
func splitRunes(s string) []string {
	runes := []rune(s)
	out := make([]string, len(runes))
	for i, r := range runes {
		out[i] = string(r)
	}
	return out
}

// inlineHighlight computes character-level diff between a and b, returning
// strings with changed segments wrapped in BoldRed (removals) and BoldGreen (additions).
func inlineHighlight(a, b string) (string, string) {
	seqA := splitRunes(a)
	seqB := splitRunes(b)

	m := difflib.NewMatcher(seqA, seqB)
	opcodes := m.GetOpCodes()

	var outA, outB strings.Builder
	for _, op := range opcodes {
		chunkA := strings.Join(seqA[op.I1:op.I2], "")
		chunkB := strings.Join(seqB[op.J1:op.J2], "")

		switch op.Tag {
		case 'e': // equal
			outA.WriteString(chunkA)
			outB.WriteString(chunkB)
		case 'r': // replace
			outA.WriteString(cliutil.BoldRed(chunkA))
			outB.WriteString(cliutil.BoldGreen(chunkB))
		case 'd': // delete (only in A)
			outA.WriteString(cliutil.BoldRed(chunkA))
		case 'i': // insert (only in B)
			outB.WriteString(cliutil.BoldGreen(chunkB))
		}
	}
	return outA.String(), outB.String()
}
