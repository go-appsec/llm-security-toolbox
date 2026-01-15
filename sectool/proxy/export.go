package proxy

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/go-harden/llm-security-toolbox/sectool/service"
)

func export(timeout time.Duration, flowID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	client, err := service.ConnectedClient(ctx, timeout)
	if err != nil {
		return err
	}

	resp, err := client.FlowExport(ctx, &service.FlowExportRequest{
		FlowID: flowID,
	})
	if err != nil {
		return fmt.Errorf("export failed: %w", err)
	}

	// Convert to relative path for cleaner output
	bundlePath := resp.BundlePath
	if workDir, err := os.Getwd(); err == nil {
		if rel, err := filepath.Rel(workDir, resp.BundlePath); err == nil {
			bundlePath = rel
		}
	}

	// Output result
	fmt.Printf("Exported flow `%s` to bundle `%s`\n\n", flowID, resp.BundleID)
	fmt.Printf("Bundle path: `%s`\n\n", bundlePath)
	fmt.Println("Files created:")
	fmt.Println("- `request.http` - HTTP headers with body placeholder")
	fmt.Println("- `body` - Request body (edit for modifications)")
	fmt.Println("- `request.meta.json` - Metadata")
	fmt.Println("\nTo replay: `sectool replay send --bundle " + bundlePath + "`")

	return nil
}
