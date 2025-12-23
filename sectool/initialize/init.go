package initialize

import "errors"

func run(mode string, reset bool) error {
	_ = reset
	switch mode {
	case "test-report":
		return errors.New("not implemented: init test-report")
	case "explore":
		return errors.New("not implemented: init explore")
	default:
		return errors.New("unknown init mode")
	}
}
