package oast

import (
	"errors"
	"time"
)

func create(timeout time.Duration) error {
	_ = timeout
	return errors.New("not implemented: oast create")
}

func poll(timeout time.Duration, oastID, since string, wait time.Duration) error {
	_, _, _, _ = timeout, oastID, since, wait
	return errors.New("not implemented: oast poll")
}

func list(timeout time.Duration) error {
	_ = timeout
	return errors.New("not implemented: oast list")
}

func del(timeout time.Duration, oastID string) error {
	_, _ = timeout, oastID
	return errors.New("not implemented: oast delete")
}
