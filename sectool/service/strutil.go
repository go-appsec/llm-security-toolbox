package service

// truncateString ensures the returned string is at most the maxLen characters,
// truncating and adding a "..." suffix if necessary.
func truncateString(str string, maxLen int) string {
	if len(str) <= maxLen || maxLen < 3 {
		return str
	}
	return str[:maxLen-3] + "..."
}
