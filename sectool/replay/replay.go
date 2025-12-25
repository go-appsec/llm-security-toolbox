package replay

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"time"

	"github.com/jentfoo/llm-security-toolbox/sectool/service"
)

func send(timeout time.Duration, flow, bundle, file, body, target string, headers, removeHeaders []string, followRedirects bool, requestTimeout time.Duration, force bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	workDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get working directory: %w", err)
	}

	client := service.NewClient(workDir, service.WithTimeout(timeout))
	if err := client.EnsureService(ctx); err != nil {
		return fmt.Errorf("failed to start service: %w (check %s)", err, client.LogPath())
	}

	req := &service.ReplaySendRequest{
		FlowID:          flow,
		BundlePath:      bundle,
		FilePath:        file,
		BodyPath:        body,
		Target:          target,
		AddHeaders:      headers,
		RemoveHeaders:   removeHeaders,
		FollowRedirects: followRedirects,
		Force:           force,
	}
	if requestTimeout > 0 {
		req.Timeout = requestTimeout.String()
	}

	resp, err := client.ReplaySend(ctx, req)
	if err != nil {
		return fmt.Errorf("replay send failed: %w", err)
	}

	// Output result as markdown
	fmt.Printf("## Replay Result\n\n")
	fmt.Printf("**Replay ID:** `%s`\n", resp.ReplayID)
	fmt.Printf("**Duration:** %s\n\n", resp.Duration)

	fmt.Printf("### Response\n\n")
	fmt.Printf("**Status:** %d %s\n", resp.Status, resp.StatusLine)
	fmt.Printf("**Size:** %d bytes\n\n", resp.RespSize)

	if resp.RespHeaders != "" {
		fmt.Printf("**Headers:**\n```\n%s```\n\n", resp.RespHeaders)
	}

	if resp.RespPreview != "" {
		fmt.Printf("**Body Preview:**\n```\n%s\n```\n", resp.RespPreview)
	}

	return nil
}

func get(timeout time.Duration, replayID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	workDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get working directory: %w", err)
	}

	client := service.NewClient(workDir, service.WithTimeout(timeout))
	if err := client.EnsureService(ctx); err != nil {
		return fmt.Errorf("failed to start service: %w (check %s)", err, client.LogPath())
	}

	resp, err := client.ReplayGet(ctx, &service.ReplayGetRequest{
		ReplayID: replayID,
	})
	if err != nil {
		return fmt.Errorf("replay get failed: %w", err)
	}

	// Output result as markdown
	fmt.Printf("## Replay Details\n\n")
	fmt.Printf("**Replay ID:** `%s`\n", resp.ReplayID)
	fmt.Printf("**Duration:** %s\n", resp.Duration)
	fmt.Printf("**Status:** %d %s\n", resp.Status, resp.StatusLine)
	fmt.Printf("**Size:** %d bytes\n\n", resp.RespSize)

	if resp.RespHeaders != "" {
		fmt.Printf("**Headers:**\n```\n%s```\n\n", resp.RespHeaders)
	}

	if resp.RespBody != "" {
		body, err := base64.StdEncoding.DecodeString(resp.RespBody)
		if err != nil {
			fmt.Printf("**Body:** (failed to decode: %v)\n", err)
		} else {
			fmt.Printf("**Body:**\n```\n%s\n```\n", string(body))
		}
	}

	return nil
}
