package encode

import (
	"encoding/base64"
	"fmt"
	"html"
	"net/url"
)

func run(input string, decode, raw bool, fn func(string, bool) (string, error)) error {
	result, err := fn(input, decode)
	if err != nil {
		return err
	}

	if raw {
		fmt.Print(result)
	} else {
		fmt.Println(result)
	}
	return nil
}

func encodeURL(input string, decode bool) (string, error) {
	if decode {
		return url.QueryUnescape(input)
	}
	return url.QueryEscape(input), nil
}

func encodeBase64(input string, decode bool) (string, error) {
	if decode {
		decoded, err := base64.StdEncoding.DecodeString(input)
		if err != nil {
			return "", fmt.Errorf("base64 decode error: %w", err)
		}
		return string(decoded), nil
	}
	return base64.StdEncoding.EncodeToString([]byte(input)), nil
}

func encodeHTML(input string, decode bool) (string, error) {
	if decode {
		return html.UnescapeString(input), nil
	}
	return html.EscapeString(input), nil
}
