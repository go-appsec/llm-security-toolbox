package proxy

import (
	"errors"
	"time"
)

func list(timeout time.Duration, host, path, method, status, contains, containsBody, since, excludeHost, excludePath string) error {
	_, _, _, _, _, _, _, _, _, _ = timeout, host, path, method, status, contains, containsBody, since, excludeHost, excludePath
	return errors.New("not implemented: proxy list")
}

func get(timeout time.Duration, flowID string) error {
	_, _ = timeout, flowID
	return errors.New("not implemented: proxy get")
}

func export(timeout time.Duration, flowID, out string) error {
	_, _, _ = timeout, flowID, out
	return errors.New("not implemented: proxy export")
}

func intercept(timeout time.Duration, state string) error {
	_, _ = timeout, state
	return errors.New("not implemented: proxy intercept (planned for future release)")
}

func ruleAdd(timeout time.Duration, host, path, method, action string) error {
	_, _, _, _, _ = timeout, host, path, method, action
	return errors.New("not implemented: proxy rule add (planned for future release)")
}

func ruleList(timeout time.Duration) error {
	_ = timeout
	return errors.New("not implemented: proxy rule list (planned for future release)")
}

func ruleRemove(timeout time.Duration, ruleID string) error {
	_, _ = timeout, ruleID
	return errors.New("not implemented: proxy rule remove (planned for future release)")
}
