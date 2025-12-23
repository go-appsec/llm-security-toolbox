package replay

import (
	"errors"
	"time"
)

func send(timeout time.Duration, flow, bundle, file, body, target string, headers, removeHeaders []string, followRedirects bool, requestTimeout time.Duration, force bool) error {
	_, _, _, _, _, _, _, _, _, _, _ = timeout, flow, bundle, file, body, target, headers, removeHeaders, followRedirects, requestTimeout, force
	return errors.New("not implemented: replay send")
}

func get(timeout time.Duration, replayID string) error {
	_, _ = timeout, replayID
	return errors.New("not implemented: replay get")
}
