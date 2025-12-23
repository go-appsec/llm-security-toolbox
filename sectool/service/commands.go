package service

import (
	"errors"
	"time"
)

func status(timeout time.Duration) error {
	_ = timeout
	return errors.New("not implemented: service status")
}

func stop(timeout time.Duration) error {
	_ = timeout
	return errors.New("not implemented: service stop")
}

func logs(timeout time.Duration, follow bool, lines int) error {
	_, _, _ = timeout, follow, lines
	return errors.New("not implemented: service logs")
}
